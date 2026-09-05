"""Executable release policy with owned files and controlled scheduler observations."""
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

SOURCE=Path(__file__).resolve().parents[1]/'INSTALL_CANONICAL_PORTABLE.ps1'


@pytest.mark.parametrize(('error','failures','calls','status'),[
    ('CONTAINER_WRITER_ADMISSION_MUTEX_TIMEOUT',2,3,'PASS'),
    ('CONTAINER_WRITER_ADMISSION_MUTEX_ABANDONED',9,6,'REJECTED'),
    ('UNRELATED_FAILURE',9,1,'REJECTED'),
])
def test_writer_release_retries_only_bounded_admission_failures(tmp_path,error,failures,calls,status):
    result=run_functions(tmp_path,SOURCE,['Invoke-CanonicalWriterFenceReleaseStep'],r'''
$script:calls=0
try {
    $value=Invoke-CanonicalWriterFenceReleaseStep {
        $script:calls++
        if ($script:calls -le [int]$env:CA_FAILURES) { throw $env:CA_ERROR }
        return 'completed'
    }
    @{status='PASS';calls=$script:calls;value=$value}|ConvertTo-Json -Compress
} catch {
    @{status='REJECTED';calls=$script:calls;error=$_.Exception.Message}|ConvertTo-Json -Compress
}
''',values={'CA_ERROR':error,'CA_FAILURES':str(failures)})
    assert result.returncode==0,result.stderr
    assert result.stderr==''
    observed=json.loads(result.stdout)
    assert observed['status']==status and observed['calls']==calls
    assert observed.get('value','completed')=='completed'
    if status=='REJECTED':
        assert observed['error']==error


@pytest.mark.parametrize(('mode','change','accepted'),[
    ('stopped','none',True),('stopped','log',False),('stopped','runtime',False),
    ('stopped','binding',False),('stopped','process',False),
    ('running','both',True),('running','log',False),('running','runtime',False),
    ('running','binding',False),('running','last_result',False),
])
def test_writer_trigger_proof_requires_matching_state_and_actual_file_observations(tmp_path,mode,change,accepted):
    result=run_functions(tmp_path,SOURCE,
        ['Sha','FileObservation','SameFileObservation','Confirm-CanonicalWriterStopped','Confirm-CanonicalWriterRunning'],r'''
# Clock and scheduler are explicit observation inputs; no real task is changed.
$script:clock=[datetime]::Parse('2026-09-06T00:00:00Z').ToUniversalTime()
function Get-Date { return $script:clock }
function Start-Sleep { param($Milliseconds,$Seconds); $script:clock=$script:clock.AddSeconds(1) }
$log=Join-Path $env:CA_CONTRACT_ROOT 'writer.log'
$runtime=Join-Path $env:CA_CONTRACT_ROOT 'writer.json'
[IO.File]::WriteAllText($log,'initial log')
[IO.File]::WriteAllText($runtime,'{"state":"initial"}')
[IO.File]::SetLastWriteTimeUtc($log,$script:clock)
[IO.File]::SetLastWriteTimeUtc($runtime,$script:clock)
$baseline=[ordered]@{enabled=($env:CA_MODE -ceq 'running');process_count=0;binding_sha256=('a'*64);
    last_run_time_utc='2026-09-05T23:00:00Z';last_task_result=0;log=(FileObservation $log);runtime_status=(FileObservation $runtime)}
$script:snapshot=[ordered]@{}
foreach ($key in $baseline.Keys) { $script:snapshot[$key]=$baseline[$key] }
if ($env:CA_MODE -ceq 'running') { $script:snapshot.last_run_time_utc='2026-09-06T00:00:01Z' }
if ($env:CA_CHANGE -cin @('log','both','binding','last_result') -and $env:CA_CHANGE -cne 'none') {
    [IO.File]::AppendAllText($log,' appended output')
    [IO.File]::SetLastWriteTimeUtc($log,$script:clock.AddSeconds(2))
}
if ($env:CA_CHANGE -cin @('runtime','both','binding','last_result')) {
    [IO.File]::WriteAllText($runtime,'{"state":"completed"}')
    [IO.File]::SetLastWriteTimeUtc($runtime,$script:clock.AddSeconds(2))
}
$script:snapshot.log=FileObservation $log
$script:snapshot.runtime_status=FileObservation $runtime
if ($env:CA_CHANGE -ceq 'binding') { $script:snapshot.binding_sha256='b'*64 }
if ($env:CA_CHANGE -ceq 'last_result') { $script:snapshot.last_task_result=1 }
if ($env:CA_CHANGE -ceq 'process') { $script:snapshot.process_count=1 }
function Get-CanonicalWriterSnapshot { param($Root); return $script:snapshot }
try {
    if ($env:CA_MODE -ceq 'stopped') {
        $proof=Confirm-CanonicalWriterStopped $env:CA_CONTRACT_ROOT @{next_run_time_utc='2026-09-06T00:00:01Z'} $baseline
    } else {
        $proof=Confirm-CanonicalWriterRunning $env:CA_CONTRACT_ROOT @{future_natural_trigger_utc='2026-09-06T00:00:01Z';readback=$baseline}
    }
    @{status=$proof.status}|ConvertTo-Json -Compress
} catch { @{status='REJECTED';error=$_.Exception.Message}|ConvertTo-Json -Compress }
''',values={'CA_MODE':mode,'CA_CHANGE':change})
    assert result.returncode==0,result.stderr
    assert result.stderr==''
    observed=json.loads(result.stdout)
    assert observed['status']==('PASS' if accepted else 'REJECTED')
    if not accepted:
        assert observed['error']==('CANONICAL_WRITER_STOP_PROOF_FAILED' if mode=='stopped'
                                   else 'CANONICAL_WRITER_NATURAL_TRIGGER_PROOF_FAILED')

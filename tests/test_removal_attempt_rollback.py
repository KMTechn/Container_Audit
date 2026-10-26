"""Per-attempt rollback keeps unrelated state and reports child damage."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from tests import test_uninstall_restore_transaction as local
from tests import test_canonical_portable_uninstall as public
from tests.powershell_contracts import run_functions


REPO = Path(__file__).resolve().parents[1]


def _local_case(tmp_path, engine, cut, *, instrument=False, shared=False, cleanup=False, legacy_no_change=False):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip('PowerShell engine unavailable')
    root = tmp_path / 'application'
    local.make_tree(root)
    driver = local.DRIVER.replace("$WriterFenceReplacementTransactionId=''", "$WriterFenceReplacementTransactionId='77777777777777777777777777777777'")
    if instrument:
        proxy = r'''
Add-Type -TypeDefinition @'
using System; using System.IO;
public class MetadataProbe {
 public static int Writes=0;
 public static void SetCreationTimeUtc(string path,DateTime time){Writes++;Directory.SetCreationTimeUtc(path,time);}
 public static void SetLastWriteTimeUtc(string path,DateTime time){Writes++;Directory.SetLastWriteTimeUtc(path,time);}
}
'@
'''
        driver = driver.replace(". (Join-Path $Repo 'tools/bootstrap_integrity.ps1')", proxy + "\n. (Join-Path $Repo 'tools/bootstrap_integrity.ps1')")
        driver = driver.replace('Invoke-Expression $node.Extent.Text', "Invoke-Expression ($node.Extent.Text.Replace('[IO.Directory]::SetCreationTimeUtc','[MetadataProbe]::SetCreationTimeUtc').Replace('[IO.Directory]::SetLastWriteTimeUtc','[MetadataProbe]::SetLastWriteTimeUtc'))")
        driver = driver.replace('$failure=$false;$guidance=$false', "$begin={throw 'INJECTED_BEFORE_CHANGE'}\n$failure=$false;$guidance=$false")
        driver += "\n[IO.File]::WriteAllText((Join-Path $Root 'metadata-writes.json'),([MetadataProbe]::Writes|ConvertTo-Json))\n"
    if shared:
        shared_dir = tmp_path / 'shared'
        shared_dir.mkdir()
        (shared_dir / 'emergency.lnk').write_bytes(b'owned shortcut')
        driver = driver.replace("$extra=Join-Path $Root '관리용/emergency.lnk'", "$extra=Join-Path (Split-Path -Parent $Root) 'shared/emergency.lnk'")
        driver = driver.replace('$failure=$false;$guidance=$false', r'''
$shared=Split-Path -Parent $extra
$expected=[DateTime]::new(2020,1,2,3,4,5,[DateTimeKind]::Utc)
$begin={[IO.Directory]::SetLastWriteTimeUtc($shared,$expected);throw 'INJECTED_BEFORE_MOVE'}
$failure=$false;$guidance=$false
''')
        driver += "\n[IO.File]::WriteAllText((Join-Path $Root 'shared-preserved.json'),(([IO.Directory]::GetLastWriteTimeUtc($shared).Ticks -eq $expected.Ticks)|ConvertTo-Json))\n"
    if cleanup:
        driver = driver.replace('$failure=$false;$guidance=$false', r'''
$script:cleanupLock=$null
$finish={
    $attempt=[IO.Directory]::GetDirectories((Join-Path $Root 'removal-evidence'))[0]
    $backup=Join-Path $attempt '.restore-preimage/0'
    $script:cleanupLock=[IO.File]::Open($backup,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
}
$failure=$false;$guidance=$false
''')
        driver = driver.replace('finally{if($null -ne $locked)',
                                'finally{if($null -ne $script:cleanupLock){$script:cleanupLock.Dispose()};if($null -ne $locked)')
    if legacy_no_change:
        setup = r'''
Add-Type -TypeDefinition @'
using System;
public class NoChangeLegacyTask {
 public int Sets=0;
 public bool Enabled {get{return true;}set{Sets++;throw new InvalidOperationException("INJECTED_DISABLE_WITHOUT_CHANGE");}}
 public string Xml {get{return "<Task><Settings><Enabled>true</Enabled></Settings></Task>";}}
 public string GetSecurityDescriptor(int flags){return "fixture-sddl";}
 public void Stop(int flags){throw new Exception("stop must not run");}
}
public class NoChangeLegacyFolder {
 public NoChangeLegacyTask Task=new NoChangeLegacyTask();
 public NoChangeLegacyTask GetTask(string name){return Task;}
}
'@
$script:legacyFolder=[NoChangeLegacyFolder]::new()
$script:legacyChainFact=$false
function Get-ContainerRemovalTaskNames {param($Folder,$CurrentRoot) return 'direct-sync-relay-container-audit'}
function Get-BootstrapOfficialLegacyRelayIdentity {param($Task,$Xml) return @{matched=$true}}
'''
        driver = driver.replace('$failure=$false;$guidance=$false', setup + '\n$failure=$false;$guidance=$false')
        driver = driver.replace('-TaskFolder $null', '-TaskFolder $script:legacyFolder')
        target = "if($cause.Message -ceq '설치 손상: 자료를 보존한 상태로 승인된 새 판을 다시 설치하세요.')"
        driver = driver.replace(target, "if($cause.Message -ceq '옛 relay 작업이 켜진 채 남음'){$script:legacyChainFact=$true};" + target)
        driver += "\n[IO.File]::WriteAllText((Join-Path $Root 'legacy.json'),(@{enabled=$script:legacyFolder.Task.Enabled;sets=$script:legacyFolder.Task.Sets;chain_fact=$script:legacyChainFact}|ConvertTo-Json))\n"
    script = tmp_path / 'rollback.ps1'
    script.write_text(driver, encoding='utf-8-sig')
    result = subprocess.run(
        [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script),
         '-Repo', str(REPO), '-Root', str(root), '-Product', 'Container', '-Cut', cut,
         '-Source', os.environ.get('SUB711_LOCAL_SOURCE', str(REPO / 'INSTALL_THIS_PC.ps1'))],
        env=dict(os.environ, PROGRAMDATA=str(tmp_path / 'programdata')),
        capture_output=True, creationflags=0x08000000,
    )
    assert result.returncode == 0, 'isolated local rollback driver failed'
    if legacy_no_change:
        (tmp_path / 'child-stdout.txt').write_bytes(result.stdout)
    return root


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_unchanged_owned_directory_metadata_is_not_written(tmp_path, engine):
    root = _local_case(tmp_path, engine, '', instrument=True)
    assert json.loads((root / 'metadata-writes.json').read_bytes()) == 0


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_shared_shortcut_parent_metadata_is_preserved(tmp_path, engine):
    root = _local_case(tmp_path, engine, '', shared=True)
    assert json.loads((root / 'shared-preserved.json').read_bytes()) is True


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_success_removes_only_its_restore_preimage(tmp_path, engine):
    root = _local_case(tmp_path, engine, 'success')
    evidence = list((root / 'removal-evidence').iterdir())
    assert len(evidence) == 1
    assert not (evidence[0] / '.restore-preimage').exists()
    assert (evidence[0] / 'current/first.bin').read_bytes() == b'first installation bytes'
    assert (root / 'business/ledger.bin').read_bytes() == b'quantity=7;membership=3'


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_preimage_cleanup_failure_preserves_success_and_reports_retained_path(tmp_path, engine):
    root = _local_case(tmp_path, engine, 'success', cleanup=True)
    assert json.loads((root / 'outcome.json').read_bytes())['failed'] is False
    marker = json.loads((root / 'removed.json').read_bytes())
    assert marker['lifecycle_state'] == 'REMOVED'
    assert any(Path(path).name == '0' and '.restore-preimage' in path for path in marker['retained_paths'])
    assert not list((root / 'removal-evidence').glob('*/rollback.json'))


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_successful_child_local_restore_marks_its_journal(tmp_path, engine):
    root = _local_case(tmp_path, engine, 'after-move')
    journals = list((root / 'removal-evidence').glob('*/removal-move-journal.jsonl'))
    assert len(journals) == 1
    records = [json.loads(line) for line in journals[0].read_text(encoding='utf-8-sig').splitlines()]
    assert records[-1]['record'] == 'RESTORED'
    assert records[-1]['files'] == sum(row['record'] == 'MOVE' for row in records)
    assert not (root / 'removed.json').exists()


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_child_leaves_unchanged_enabled_task_and_records_the_fact(tmp_path, engine):
    root = _local_case(tmp_path, engine, 'task-no-change', legacy_no_change=True)
    outcome = json.loads((root / 'outcome.json').read_bytes())
    assert outcome == {'failed': True, 'guidance': False}
    assert json.loads((root / 'legacy.json').read_bytes()) == {'enabled': True, 'sets': 1, 'chain_fact': True}
    assert '옛 relay 작업이 켜진 채 남음' in (tmp_path / 'child-stdout.txt').read_text(encoding='utf-8', errors='replace')
    assert not list((root / 'removal-evidence').glob('*/rollback.json'))
    journal = next((root / 'removal-evidence').glob('*/removal-move-journal.jsonl'))
    assert json.loads(journal.read_text(encoding='utf-8-sig').splitlines()[-1])['record'] == 'RESTORED'


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_audit_keeps_only_the_approved_relay_fact_in_existing_diagnostic_slots(tmp_path, engine):
    script = r'''
$fact='옛 relay 작업이 켜진 채 남음'
$child=[pscustomobject]@{ProcessId=7;ExitCode=1;Streams=@{};Stdout=('PRIVATE_VALUE'+[Environment]::NewLine+$fact+[Environment]::NewLine+'PRIVATE_VALUE');Stderr='PRIVATE_VALUE'}
$audit=@{removal_child_failure=(Get-CanonicalRetirementChildFailure $child);failure=@{exception_chain=@(@{message=$fact},@{message=('PRIVATE_VALUE '+$fact)})}}
$json=ConvertTo-CanonicalAuditJson $audit
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'audit.json'),$json,[Text.UTF8Encoding]::new($false))
'''
    result = run_functions(tmp_path, REPO / 'INSTALL_CANONICAL_PORTABLE.ps1',
                           ['Get-CanonicalRetirementChildFailure', 'ConvertTo-CanonicalAuditJson'], script, engine=engine)
    assert result.returncode == 0, 'isolated diagnostic carrier failed'
    raw = (tmp_path / 'audit.json').read_text(encoding='utf-8-sig')
    value = json.loads(raw)
    assert value['removal_child_failure']['stdout'] == '옛 relay 작업이 켜진 채 남음'
    assert value['failure']['exception_chain'][0]['message'] == '옛 relay 작업이 켜진 채 남음'
    assert value['removal_child_failure']['stderr'] == 'SUPPORT_FAILURE'
    assert value['failure']['exception_chain'][1]['message'] == 'SUPPORT_FAILURE'
    assert 'PRIVATE_VALUE' not in raw


@pytest.mark.parametrize('engine', ['powershell.exe', 'pwsh.exe'])
def test_attempt_journal_selection_ignores_earlier_same_transaction(tmp_path, engine):
    app = tmp_path / 'application'
    paths = []
    for name in ('previous', 'current'):
        evidence = app / 'removal-evidence' / name
        evidence.mkdir(parents=True)
        journal = evidence / 'removal-move-journal.jsonl'
        journal.write_text(json.dumps(dict(record='HEADER', run_id='7' * 32)) + '\n')
        paths.append(journal)
    script = r'''
$app=Join-Path $env:CA_CONTRACT_ROOT 'application'
$old=Join-Path $app 'removal-evidence/previous/removal-move-journal.jsonl'
$ambiguous=$false
try{[void](Find-CanonicalRemovalMoveJournal $app ('7'*32))}catch{$ambiguous=($_.Exception.Message -ceq 'MACHINE_RECOVERY_REMOVAL_JOURNAL_AMBIGUOUS')}
if(-not $ambiguous){throw 'multiple new journals accepted'}
$selected=Find-CanonicalRemovalMoveJournal $app ('7'*32) -ExcludedJournals @($old)
if($selected -cne (Join-Path $app 'removal-evidence/current/removal-move-journal.jsonl')){throw 'wrong attempt selected'}
$none=Find-CanonicalRemovalMoveJournal $app ('7'*32) -ExcludedJournals @($old,$selected)
if($null -ne $none){throw 'earlier journal reused'}
'''
    result = run_functions(tmp_path, REPO / 'INSTALL_CANONICAL_PORTABLE.ps1',
                           ['Find-CanonicalRemovalMoveJournal'], script, engine=engine)
    assert result.returncode == 0, 'same transaction must select only this invocation journal'


def test_local_rollback_has_no_foreign_product_task_command():
    text = (REPO / 'INSTALL_THIS_PC.ps1').read_text(encoding='utf-8-sig')
    start = text.index('function Invoke-ContainerConvergentRemoval(')
    end = text.index('function ', text.index('\n}', start) + 2)
    assert 'Invoke-LabelOfficialLegacyTaskTransition' not in text[start:end]


@pytest.mark.parametrize('damage', [False, True])
def test_public_parent_preserves_the_child_rollback_verdict(tmp_path, damage):
    env, source, install, protected = public._setup(
        tmp_path, 'child_restore_failure' if damage else 'partial')
    original_data = {path: path.read_bytes() for path in protected}
    result = public._run(tmp_path, env, source, install)
    assert result.returncode == 1
    outputs = [json.loads(line.split('=', 1)[1]) for line in result.stdout.splitlines()
               if line.startswith('CONTAINER_AUDIT_INSTALL_CANONICAL=')]
    assert len(outputs) == 1
    assert outputs[0]['exit_code'] == 1
    record = json.loads(Path(result.fixture_audit['audit_path']).read_bytes())
    assert record['rollback']['runtime_restored'] is (not damage)
    evidence = list((install.parent / 'removal-evidence').iterdir())
    assert len(evidence) == 1, 'damage must stay in the same removal attempt'
    journal = evidence[0] / 'removal-move-journal.jsonl'
    entries = [json.loads(line) for line in journal.read_text(encoding='utf-8-sig').splitlines()]
    if damage:
        rollback = json.loads((evidence[0] / 'rollback.json').read_bytes())
        assert rollback['status'] == 'ROLLBACK_FAILED'
        assert rollback['failure_types']
        assert not any(row['record'] == 'RESTORED' for row in entries)
        assert outputs[-1]['guidance'] == '설치 손상: 자료를 보존한 상태로 승인된 새 판을 다시 설치하세요.'
    else:
        assert sum(row['record'] == 'RESTORED' for row in entries) == 1
        assert install.is_dir()
    assert {path: path.read_bytes() for path in protected} == original_data
    assert not (install.parent / 'removed.json').exists()


def test_parent_preserves_child_failure_types_when_own_compensation_also_fails(tmp_path):
    env, source, install, protected = public._setup(tmp_path, 'child_and_parent_restore_failure')
    original_data = {path: path.read_bytes() for path in protected}
    result = public._run(tmp_path, env, source, install)
    assert result.returncode != 0
    record = json.loads(Path(result.fixture_audit['audit_path']).read_bytes())
    assert record['rollback']['runtime_restored'] is False
    reports = list((install.parent / 'removal-evidence').glob('*/rollback.json'))
    assert len(reports) == 1
    failure = json.loads(reports[0].read_bytes())
    assert 'System.Management.Automation.RuntimeException' in failure['failure_types']
    assert 'System.IO.IOException' in failure['failure_types']
    assert {path: path.read_bytes() for path in protected} == original_data

import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import ast
import pytest

import writer_session_fence as fence


ROOT = Path(__file__).resolve().parents[1]
WINPS = Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'


def _exercise_transition(tmp_path, old_root):
    old_source = (old_root/'writer_session_fence.py').read_text(encoding='utf-8')
    old_pin = re.search(r'WRITER_INVENTORY_SHA256\s*=\s*["\']([0-9a-f]{64})', old_source)[1]
    assert old_pin != fence.WRITER_INVENTORY_SHA256
    child = tmp_path/'child.py'
    child.write_text(r'''
import os, sys
from pathlib import Path
sys.path[:0] = [sys.argv[1], os.environ['CA_TEST_SOURCE']]
import writer_session_fence as fence
root = Path(os.environ['CA_TEST_CONTROL'])
mutex = os.environ['CA_TEST_MUTEX']
assert mutex != fence.WRITER_MUTEX_NAME
fence.canonical_control_root = lambda environ=None: root
fence.writer_admission_mutex_name = lambda root, environ=None: mutex
import current_user_onboarding as onboarding
# Keep the actual product dispatcher, admission, removal body and report. Only
# the OS boundaries are isolated so no controller HKCU or process is changed.
removal = onboarding.remove_current_user_setup
defaults = getattr(removal, '__wrapped__', removal).__kwdefaults__
defaults['autostart_remover'] = lambda: {'status': 'ABSENT'}
defaults['relay_stopper'] = lambda root: {'status': 'ABSENT'}
from container_audit_product_host import dispatch_product_mode
try:
    result = dispatch_product_mode(['--remove-current-user-setup', '--app-root', sys.argv[1]])
except fence.WriterFenceError as exc:
    print(exc.code)
    raise SystemExit(23)
raise SystemExit(result)
''', encoding='utf-8')
    script = tmp_path/'transition.ps1'
    script.write_text(r'''
$ErrorActionPreference = 'Stop'
. (Join-Path $env:CA_TEST_SOURCE 'tools\container_writer_fence.ps1')
$root = $env:CA_TEST_CONTROL
$env:CA_TEST_MUTEX = Get-ContainerWriterAdmissionMutexName $root
if ($env:CA_TEST_MUTEX -ceq $Script:ContainerWriterFenceAdmissionMutexName) { throw 'not isolated' }
$s = [Guid]::NewGuid().ToString('N'); $a = '1'*32; $t = [Guid]::NewGuid().ToString('N')
$authority = Enter-ContainerWriterSessionAuthority $s $a ('2'*64) $t ('4'*64)
$token = 'test-delegation-token'*4
$prepared = Join-Path $env:CA_TEST_TMP 'prepared.json'
[IO.File]::WriteAllText($prepared, '{"status":"PREPARED"}')
$sha = Get-ContainerWriterFenceFileSha256 $prepared
$bindings = @{ControlRoot=$root;SessionId=$s;AttemptId=$a;ReplacementTransactionId=$t;AuthorityLease=$authority}
$env:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN=$token
$env:CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID=$s
$env:CONTAINER_AUDIT_WRITER_DELEGATION_ATTEMPT_ID=$a
$env:CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID=$t
function Child([string]$RootPath, [int]$Expected, [string]$Code) {
    $output = @(& $env:CA_TEST_PYTHON -I -B (Join-Path $env:CA_TEST_TMP 'child.py') $RootPath)
    if ($LASTEXITCODE -ne $Expected -or ($Code -and ($output -join "`n") -notmatch $Code)) {
        throw "child mismatch $Expected/$LASTEXITCODE $($output -join ' ')"
    }
}
try {
    [void](Start-ContainerWriterFence @bindings -Status INSTALLING -OwnerKind canonical_installer `
        -SessionStartedAtUtc ([DateTime]::UtcNow.ToString('o')) -OrchestratorSha256 ('2'*64) `
        -WriterContractSha256 ('4'*64) -PreparedReceiptPath $prepared -PreparedReceiptSha256 $sha `
        -DelegationToken $token -DelegatedSources @('current_user_onboarding_storage','current_user_setup_removal') `
        -DelegationExpiresAtUtc ([DateTime]::UtcNow.AddMinutes(5).ToString('o')))
    Child $env:CA_TEST_OLD 23 'FENCE_BINDING_INVALID'
    Child $env:CA_TEST_SOURCE 0 'PASS_DATA_PRESERVED'
    try { [void](Set-ContainerWriterFenceInventory @bindings -WriterInventorySha256 $env:CA_TEST_OLD_PIN); throw 'accepted unverified old hash' }
    catch { if ($_.Exception.Message -cne 'CONTAINER_WRITER_FENCE_INVENTORY_TRANSITION_INVALID') { throw } }
    # Unit-level setup models the canonical installer's already verified tree.
    $Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = $env:CA_TEST_OLD_PIN
    $before = Get-Content (Get-ContainerWriterFenceActivePath $root) -Raw
    try { [void](Set-ContainerWriterFenceInventory @bindings -WriterInventorySha256 ('f'*64)); throw 'accepted third hash' }
    catch { if ($_.Exception.Message -cne 'CONTAINER_WRITER_FENCE_INVENTORY_TRANSITION_INVALID') { throw } }
    $wrong = $bindings.Clone(); $wrong.AttemptId='9'*32
    try { [void](Set-ContainerWriterFenceInventory @wrong -WriterInventorySha256 $env:CA_TEST_OLD_PIN); throw 'accepted foreign session' }
    catch { if ($_.Exception.Message -cne 'CONTAINER_WRITER_FENCE_INVENTORY_TRANSITION_INVALID') { throw } }
    if ((Get-Content (Get-ContainerWriterFenceActivePath $root) -Raw) -cne $before) { throw 'rejection mutated fence' }
    [void](Set-ContainerWriterFenceInventory @bindings -WriterInventorySha256 $env:CA_TEST_OLD_PIN)
    Child $env:CA_TEST_OLD 0 'PASS_DATA_PRESERVED'
    $env:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN=''
    Child $env:CA_TEST_OLD 23 'ACTIVE_WRITER_FENCE'
    $env:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN=$token
    Child $env:CA_TEST_SOURCE 23 'FENCE_BINDING_INVALID'
    [void](Set-ContainerWriterFenceInventory @bindings -WriterInventorySha256 $Script:ContainerWriterFenceInventorySha256)
    Child $env:CA_TEST_SOURCE 0 'PASS_DATA_PRESERVED'
    # A later placement/product failure restores old bytes, then quiesces them
    # under their own identity and releases before the undelegated restart.
    try { throw 'injected later phase failure' }
    catch {
        [void](Set-ContainerWriterFenceInventory @bindings -WriterInventorySha256 $env:CA_TEST_OLD_PIN)
        Child $env:CA_TEST_OLD 0 'PASS_DATA_PRESERVED'
        $release = Stop-ContainerWriterFence @bindings -ReleaseAuthorizationPath $prepared -ReleaseAuthorizationSha256 $sha
        if ($release.writer_inventory_sha256 -cne $env:CA_TEST_OLD_PIN) { throw 'release identity mismatch' }
    }
    if (Test-Path (Get-ContainerWriterFenceActivePath $root)) { throw 'stale active fence' }
    $env:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN=''
    Child $env:CA_TEST_OLD 0 'PASS_DATA_PRESERVED'
    'TRANSITION_AND_ROLLBACK_PASS'
} finally { Exit-ContainerWriterSessionAuthority $authority }
''', encoding='utf-8')
    environment = dict(os.environ)
    environment.update({
        'CA_TEST_SOURCE':str(ROOT),'CA_TEST_OLD':str(old_root),'CA_TEST_OLD_PIN':old_pin,
        'CA_TEST_TMP':str(tmp_path),'CA_TEST_CONTROL':str(tmp_path/'control'),
        'CA_TEST_PYTHON':sys.executable,'LOCALAPPDATA':str(tmp_path/'local'),
        'CONTAINER_AUDIT_DATA_ROOT':str(tmp_path/'business'),
    })
    completed = subprocess.run([str(WINPS),'-NoProfile','-NonInteractive','-File',str(script)],
        env=environment, capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert 'TRANSITION_AND_ROLLBACK_PASS' in completed.stdout


def test_removal_read_probe_has_one_admitted_production_call_site():
    calls = []
    for path in ROOT.rglob('*.py'):
        relative = path.relative_to(ROOT)
        if relative.parts[0] in ('tests', '.git', 'site-packages'):
            continue
        tree = ast.parse(path.read_text(encoding='utf-8-sig'))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            argument = next((a.value for a in node.keywords if a.arg == 'admission_source'), None)
            if isinstance(argument, ast.Constant):
                calls.append((relative.as_posix(), tree, node, argument.value))
    assert len(calls) == 1
    relative, tree, call, source = calls[0]
    assert relative == 'current_user_onboarding.py'
    assert source == 'current_user_setup_removal'
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == 'remove_current_user_setup')
    assert function.lineno < call.lineno <= function.end_lineno
    scopes = [n for n in ast.walk(function) if isinstance(n, ast.With)
              and n.lineno < call.lineno <= n.end_lineno]
    assert any(isinstance(item.context_expr, ast.Call)
               and isinstance(item.context_expr.func, ast.Name)
               and item.context_expr.func.id == 'writer_admission'
               and isinstance(item.context_expr.args[0], ast.Constant)
               and item.context_expr.args[0].value == source
               for scope in scopes for item in scope.items)
    guard_tree = ast.parse((ROOT/'data_generation_guard.py').read_text(encoding='utf-8-sig'))
    probe = next(n for n in guard_tree.body if isinstance(n, ast.FunctionDef)
                 and n.name == 'probe_before_data_open')
    unwrapped = [n for n in ast.walk(probe) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == '__wrapped__']
    assert len(unwrapped) == 1
    assert isinstance(unwrapped[0].func.value, ast.Name)
    assert unwrapped[0].func.value.id == 'record_before_data_open'
    assert [(a.arg, a.value.value) for a in unwrapped[0].keywords
            if isinstance(a.value, ast.Constant)] == [('probe_only', True)]


@pytest.mark.parametrize('marker_state', ('missing', 'same', 'newer', 'unknown'))
def test_admitted_removal_probe_preserves_metadata_and_refusal_state(tmp_path, marker_state):
    child = tmp_path/'readonly_removal.py'
    child.write_text(r'''
import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import data_generation_guard as guard
import current_user_onboarding as onboarding
from writer_session_fence import writer_admission, canonical_control_root
data = Path(os.environ['CONTAINER_AUDIT_DATA_ROOT'])
control = canonical_control_root()
for root in (data, control):
    root.mkdir(parents=True, exist_ok=True)
    (root/'preserved.txt').write_text('preserved')
state = sys.argv[2]
if state != 'missing':
    guard.record_before_data_open(data)
    marker = data/'data-generation.json'
    if state == 'newer':
        document = json.loads(marker.read_bytes())
        release = guard._runtime_release()
        release['version'] = '999.0.0'
        guard.generation.record_generation(marker, app_id='container_audit',
                                           subject_sid=document['subject_sid'], **release)
    elif state == 'unknown':
        marker.write_bytes(b'{invalid')
def snapshot():
    return sorted((i, p.relative_to(root).as_posix(), p.is_dir(),
                   p.stat().st_size, p.stat().st_mtime_ns)
                  for i, root in enumerate((data, control)) for p in [root, *root.rglob('*')])
before = snapshot()
decision = 'ALLOW'
with writer_admission('current_user_setup_removal'):
    try:
        guard.probe_before_owner_paths(data, admission_source='current_user_setup_removal')
    except guard.DataGenerationBlocked as exc:
        decision = exc.decision['status']
assert snapshot() == before, 'read-only probe changed file list, size or mtime'
if state == 'missing':
    assert not (data/'data-generation.json').exists(), 'read-only probe created a data marker'
    assert not (control/'data-generation').exists(), 'read-only probe created a control marker'
calls = []
def autostart():
    calls.append('autostart')
    return {'status': 'ABSENT'}
def relay(root):
    calls.append('relay')
    return {'status': 'ABSENT'}
before_removal = snapshot()
try:
    result = onboarding.remove_current_user_setup(sys.argv[1], autostart_remover=autostart,
                                                  relay_stopper=relay)
except onboarding.CurrentUserOnboardingError as exc:
    assert state in ('newer', 'unknown'), 'normal removal was refused'
    assert isinstance(exc.__cause__, guard.DataGenerationBlocked), 'G refusal was replaced'
    assert not calls, 'G refusal changed relay/autostart'
    assert snapshot() == before_removal, 'G refusal changed data/control metadata'
else:
    assert state in ('missing', 'same'), 'newer/unknown marker was admitted'
    assert result['status'] == 'PASS_DATA_PRESERVED'
    assert calls == ['autostart', 'relay']
assert decision == {'missing':'ALLOW', 'same':'ALLOW', 'newer':'REFUSE', 'unknown':'UNKNOWN'}[state]
print('READ_ONLY_PROBE_AND_REMOVAL_ORACLES_PASS')
''', encoding='utf-8')
    environment = dict(os.environ, LOCALAPPDATA=str(tmp_path/'local'),
                       CONTAINER_AUDIT_DATA_ROOT=str(tmp_path/'business'))
    result = subprocess.run([sys.executable, '-I', '-B', str(child), str(ROOT), marker_state],
                            env=environment, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'READ_ONLY_PROBE_AND_REMOVAL_ORACLES_PASS' in result.stdout


def test_old_new_inventory_switch_keeps_real_child_admission_and_rollback_exact(tmp_path):
    old_root = tmp_path/'old-code'
    old_root.mkdir()
    source = (ROOT/'writer_session_fence.py').read_text(encoding='utf-8')
    (old_root/'writer_session_fence.py').write_text(source.replace(fence.WRITER_INVENTORY_SHA256, 'a'*64),encoding='utf-8')
    _exercise_transition(tmp_path, old_root)




def test_inventory_compatibility_uses_sink_identities_and_guards_not_caller_counts(tmp_path):
    environment = dict(os.environ, CA_TEST_SOURCE=str(ROOT))
    command = r'''
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:CA_TEST_SOURCE 'INSTALL_CANONICAL_PORTABLE.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'parse errors' }
$function=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-WriterInventorySemantics'},$true)
Invoke-Expression $function[0].Extent.Text
$path=Join-Path $env:CA_TEST_SOURCE 'tools\container_writer_sink_inventory.json'
$old=Get-Content $path -Raw | ConvertFrom-Json
$new=Get-Content $path -Raw | ConvertFrom-Json
$expected=Get-WriterInventorySemantics $old
$new.inventory_sha256='a'*64
$new.writer_sinks[0].line=99999
$new.powershell_writer_sinks[0].writer_site_count+=6
$new.closure_direct_mutation_functions[0].direct_callers=@('added-existing-sink-caller')
if ((Get-WriterInventorySemantics $new) -cne $expected) { throw 'metadata-only membership mismatch' }
$new.writer_sinks[0].function='forged-writer'
if ((Get-WriterInventorySemantics $new) -ceq $expected) { throw 'forged writer accepted' }
$new=Get-Content $path -Raw | ConvertFrom-Json
$new.writer_sink_sources+=@('forged-source')
if ((Get-WriterInventorySemantics $new) -ceq $expected) { throw 'forged delegation accepted' }
$new=Get-Content $path -Raw | ConvertFrom-Json
$new.powershell_writer_sinks[0].guard_name='forged-guard'
if ((Get-WriterInventorySemantics $new) -ceq $expected) { throw 'forged guard accepted' }
$new=Get-Content $path -Raw | ConvertFrom-Json
$new.powershell_writer_sinks[0].guarded=$false
if ((Get-WriterInventorySemantics $new) -ceq $expected) { throw 'unguarded writer accepted' }
$new=Get-Content $path -Raw | ConvertFrom-Json
$new.powershell_writer_sinks[0].writer_site_kinds+=@('foreign-kind')
if ((Get-WriterInventorySemantics $new) -ceq $expected) { throw 'changed writer kinds accepted' }
'MEMBERSHIP_REJECTIONS_PASS'
'''
    completed = subprocess.run([str(WINPS),'-NoProfile','-NonInteractive','-Command',command],
        env=environment,capture_output=True,text=True,timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr

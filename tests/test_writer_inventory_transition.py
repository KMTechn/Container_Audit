import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

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
defaults = onboarding.remove_current_user_setup.__wrapped__.__kwdefaults__
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
$s = '0'*32; $a = '1'*32; $t = '3'*32
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


def test_old_new_inventory_switch_keeps_real_child_admission_and_rollback_exact(tmp_path):
    old_root = tmp_path/'old-code'
    old_root.mkdir()
    source = (ROOT/'writer_session_fence.py').read_text(encoding='utf-8')
    (old_root/'writer_session_fence.py').write_text(source.replace(fence.WRITER_INVENTORY_SHA256, 'a'*64),encoding='utf-8')
    _exercise_transition(tmp_path, old_root)


def test_installer_rejects_incompatible_prestate_before_fence_and_restores_relay_after_release():
    source = (ROOT/'INSTALL_CANONICAL_PORTABLE.ps1').read_text(encoding='utf-8')
    precheck = source.index('$preflightCandidate = InstalledManifest')
    integrity = source.index('Assert-BootstrapIntegrityRecord $install', precheck)
    membership = source.index('CODE_PRESTATE_WRITER_SEMANTICS_DIFFER', integrity)
    snapshot = source.index('$old = @(Relays)', membership)
    activation = source.index('[void](Start-ContainerWriterFence', snapshot)
    assert precheck < integrity < membership < snapshot < activation
    old_sync = source.index('Sync-CanonicalWriterFenceInventory $installedInventorySha256', activation)
    old_call = source.index("Product $install '--remove-current-user-setup'", old_sync)
    new_sync = source.index('Sync-CanonicalWriterFenceInventory $Script:ContainerWriterFenceInventorySha256', old_call)
    placement = source.index('& $winps @bootstrap', new_sync)
    restore = source.index('$currentTreeInventorySha256 = $installedInventorySha256', placement)
    rollback_sync = source.index('Sync-CanonicalWriterFenceInventory $currentTreeInventorySha256', restore)
    rollback_call = source.index("Product $install '--remove-current-user-setup'", rollback_sync)
    release = source.index("-Phase 'ROLLBACK_COMPLETE'", rollback_call)
    release = source.index('Stop-CanonicalWriterFenceRelease $releaseAuthorization', release)
    restart = source.index('$newPid = StartRaw', release)
    assert old_sync < old_call < new_sync < placement < restore < rollback_sync < rollback_call < release < restart
    assert "$Script:ContainerWriterFenceAcceptedInstalledInventorySha256 = ''" in source[source.rindex('finally {'):]


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
'MEMBERSHIP_REJECTIONS_PASS'
'''
    completed = subprocess.run([str(WINPS),'-NoProfile','-NonInteractive','-Command',command],
        env=environment,capture_output=True,text=True,timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr

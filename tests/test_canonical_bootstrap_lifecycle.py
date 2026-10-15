"""Run the real startup function groups; replace only native process boundaries."""
from pathlib import Path
import json
import os
import re

import pytest

import auto_update
import current_user_onboarding as onboarding
import user_relay
import writer_session_fence as fence
from tests.powershell_contracts import run_functions
from tests.test_current_user_onboarding import (
    existing_possession_key_contract, _ready_state, _profile_loader,
    _credential_loader, _ledger_factory, _autostart,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"
SHA = "1" * 40


@pytest.mark.usefixtures("existing_possession_key_contract")
def test_real_onboarding_defers_relay_under_valid_installation_delegation(monkeypatch, tmp_path):
    from datetime import datetime, timedelta, timezone
    import hashlib
    from types import SimpleNamespace

    # The native fence observation is isolated, but actual admission/delegation,
    # onboarding, relay start, and bootstrap function bodies remain in use.
    token = "synthetic-delegation-fixture-value-never-persist"
    session, attempt, transaction = "a" * 32, "b" * 32, "c" * 32
    for name, value in ((fence.DELEGATION_TOKEN_ENV, token), (fence.DELEGATION_SESSION_ENV, session),
                        (fence.DELEGATION_ATTEMPT_ENV, attempt), (fence.DELEGATION_TRANSACTION_ENV, transaction)):
        monkeypatch.setenv(name, value)
    sources = json.loads((ROOT / "tools/container_writer_sink_inventory.json").read_text(encoding="utf-8"))["writer_sink_sources"]
    active = {"status": "INSTALLING", "delegated_sources": sources, "session_id": session,
              "attempt_id": attempt, "replacement_transaction_id": transaction,
              "delegation_expires_at_utc": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
              "session_authority_mutex_name": "isolated-fence-observation",
              "delegation_sha256": hashlib.sha256(token.encode()).hexdigest()}
    monkeypatch.setattr(fence, "active_fence", lambda *args, **kwargs: active)
    monkeypatch.setattr(fence, "_named_mutex_held_by_other", lambda name: True)
    app = tmp_path / "managed/current/app"
    app.mkdir(parents=True)
    control = app.parent.parent / "update-control"
    control.mkdir()
    (control / "policy.json").write_text(json.dumps({"operator_sid": auto_update.current_process_sid()}), encoding="utf-8")
    (control / "active.json").write_text(json.dumps({"sha": SHA}), encoding="utf-8")
    (app.parent / "portable-manifest.json").write_text(json.dumps({"source_commit": SHA}), encoding="utf-8")
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    _ready_state(paths)
    monkeypatch.setattr(auto_update, "ordinary_user_context", lambda *args: False)
    launches = []
    # Relay interception must not replace the G adapter's exact read-only
    # source-identity probes with a relay-shaped fake process.
    original_popen = user_relay.subprocess.Popen
    for name in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        monkeypatch.delenv(name, raising=False)
    metadata_commands = (
        ["git", "--no-optional-locks", "-C", str(ROOT), "status", "--porcelain"],
        ["git", "--no-optional-locks", "-C", str(ROOT), "rev-parse", "HEAD^{commit}"],
    )

    def launch(command, **kwargs):
        if list(command) in metadata_commands:
            return original_popen(command, **kwargs)
        launches.append(list(command))
        # Exercise the child's real admission rather than claiming Popen PID
        # means a resident relay. No native child is started.
        with pytest.raises(ValueError, match="installed ordinary operator"):
            auto_update.bootstrap(app, [user_relay.USER_RELAY_MODE], role="relay")
        return SimpleNamespace(pid=6789)
    monkeypatch.setattr(user_relay.subprocess, "Popen", launch)
    report = onboarding.onboard_current_user(app, environ=environment, require_bootstrap_integrity=False,
        registration_runner=lambda paths: 0, profile_loader=_profile_loader,
        credential_loader=_credential_loader, ledger_factory=_ledger_factory,
        autostart_installer=_autostart, relay_launcher=user_relay.start_user_relay_process)
    assert report["status"] == "READY"
    assert report["relay_start"] == {"status": "DEFERRED_CANONICAL_RELEASE", "process_id": 0}
    assert launches == []


def test_normal_managed_relay_publishes_its_actual_pid_and_version(monkeypatch, tmp_path):
    control = tmp_path / "managed" / "update-control"
    app = control.parent / "versions" / SHA / "app"
    monkeypatch.setattr(auto_update, "control_root", lambda root: control)
    monkeypatch.setattr(auto_update, "optional_record", lambda path: None)
    monkeypatch.setattr(auto_update, "version_manifest", lambda root: {"source_commit": SHA})
    monkeypatch.setattr(auto_update, "read_json", lambda path: {"operator_sid": "S-1-5-21-111-222-333-1001"})
    monkeypatch.setattr(auto_update, "ordinary_user_context", lambda *args: True)
    report = auto_update.relay_ready_metadata(app)
    assert report.get("process_id") == os.getpid()
    assert report.get("source_commit") == SHA
    assert report.get("ordinary_user") is True
    assert "update_nonce" not in report


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("mode", ("restart", "preimage", "lifecycle"))
def test_real_startup_accepts_live_version_relay_after_bootstrap_exit(tmp_path, engine, mode):
    # Whole top-level product functions, including newly introduced dependencies,
    # are loaded without executing the installer entrypoint.
    names = re.findall(r"^function\s+([^\s(]+)", SOURCE.read_text(encoding="utf-8-sig"), re.M)
    result = run_functions(tmp_path, SOURCE, names, r'''
$managed=Join-Path $env:CA_CONTRACT_ROOT 'managed';$install=Join-Path $managed 'current'
$sha=('1'*40);$version=Join-Path $managed ('versions\'+$sha)
$control=Join-Path $managed 'update-control'
foreach($p in @((Join-Path $install 'app'),(Join-Path $version 'app'),(Join-Path $version 'runtime'),$control)){[void][IO.Directory]::CreateDirectory($p)}
[IO.File]::WriteAllText((Join-Path $install 'app\auto-update-settings.json'),'{}')
[IO.File]::WriteAllText((Join-Path $version 'runtime\pythonw.exe'),'inert runtime fixture')
[IO.File]::WriteAllText((Join-Path $version 'app\main.py'),'inert entry fixture')
[IO.File]::WriteAllText((Join-Path $version 'portable-manifest.json'),(@{source_commit=$sha;startup_update_protocol=1;relay_identity_protocol=1}|ConvertTo-Json))
[IO.File]::WriteAllText((Join-Path $control 'active.json'),(@{schema='container-audit-startup-update-v1';sha=$sha;transition_id='fixture'}|ConvertTo-Json))
[IO.File]::WriteAllText((Join-Path $control 'policy.json'),(@{operator_sid='S-1-5-21-111-222-333-1001'}|ConvertTo-Json))
$inventory=@(Get-CodeInventory $version)
[IO.File]::WriteAllText((Join-Path $version 'bootstrap-integrity.json'),(@{schema_version=$BootstrapIntegritySchema;status='PASS';code_root=$install;file_count=$inventory.Count;files=$inventory;aggregate_sha256=(Get-InventoryAggregate $inventory)}|ConvertTo-Json -Depth 8))
$env:CONTAINER_AUDIT_DATA_ROOT='';$SourceRoot=$install
$wanted=Command $install -Installed
$actualCommand=(Arg (Join-Path $version 'runtime\pythonw.exe'))+' -I -B '+(Arg (Join-Path $version 'app\main.py'))+' --container-audit-user-relay'
$live=[pscustomobject]@{ProcessId=4111;ExecutablePath=(Join-Path $version 'runtime\pythonw.exe');CommandLine=$actualCommand;CreationDate=[DateTime]::UtcNow}
$relayPath=Join-Path $env:CA_CONTRACT_ROOT 'relay.json'
$script:launched=$false
function Get-CanonicalRelaySecurity([int]$ProcessId){return [pscustomobject]@{sid='S-1-5-21-111-222-333-1001';session_id=1;elevated=($ProcessId -eq $PID)}}
function Start-CanonicalLimitedRelay([string]$Line,[string]$UserSid,[int]$SessionId){
 if($Line -cne $wanted){throw 'wrong Run command'};$script:launched=$true
 $live.CreationDate=[DateTime]::UtcNow
 [IO.File]::WriteAllText($relayPath,(@{report_version='container-audit-user-relay-v1';status='RUNNING';principal='current_user';persistent_retry=$true;process_id=4111;source_commit=$sha;ordinary_user=$true;updated_at=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
 return 3111
}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) if($Filter -ceq 'ProcessId = 4111'){return $live};return $null}
function Relays {if($script:launched -or $env:CA_BOOTSTRAP_MODE -ceq 'preimage'){return @($live)};return @()}
function Start-Sleep {}
# File access is real isolated I/O. Only native protected-ACL observation is
# replaced; this test cannot change host/product ACLs or start a relay.
function Assert-BootstrapProtectedRelayPath {return @()}
function Assert-BootstrapNoReparsePoint {}
function Get-CanonicalRelaySecurityCaller {return Get-CanonicalRelaySecurity $PID}
if($env:CA_BOOTSTRAP_MODE -ceq 'lifecycle'){
 $adapter=Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools\container_writer_session.ps1'
 $tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseFile($adapter,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'real lifecycle adapter parse failed'}
 foreach($definition in @($tree.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})){Invoke-Expression $definition.Extent.Text}
 $Script:UserRelayMode='--container-audit-user-relay';$Script:EvidenceClockTolerance=[TimeSpan]::FromSeconds(2)
 [void](StartRaw $wanted)
 $live|Add-Member -NotePropertyName OwnerSid -NotePropertyValue 'S-1-5-21-111-222-333-1001'
 $receipt=[pscustomobject]@{captured_at=[DateTime]::UtcNow.AddSeconds(-1).ToString('o');completed_at=[DateTime]::UtcNow.ToString('o');
  relay_autostart=[pscustomobject]@{status='PASS';principal='current_user';registry_hive='HKEY_CURRENT_USER';registry_key='Software\Microsoft\Windows\CurrentVersion\Run';registry_value='KMTech.ContainerAudit.Relay';command=$wanted};
  relay_start=[pscustomobject]@{status='START_REQUESTED';process_id=3111}}
 $status=Get-Content -LiteralPath $relayPath -Raw -Encoding UTF8|ConvertFrom-Json
 $observation=[pscustomobject]@{registry_command=$wanted;registry_value_kind='String';current_user_sid='S-1-5-21-111-222-333-1001';candidates=@($live);
  caller_security=(Get-CanonicalRelaySecurity $PID);process_security=@{'4111'=(Get-CanonicalRelaySecurity 4111)};runtime_status=$status}
 $provider={return $observation}.GetNewClosure()
 if(-not(Test-ContainerUserRelayLiveReadback $receipt $install $provider)){throw 'lifecycle rejected real resident version identity after launcher exit'}
}elseif($env:CA_BOOTSTRAP_MODE -ceq 'preimage'){
 $before=@{exists=$true;kind='String';data=$wanted}
 $binding=Assert-CanonicalRuntimePreimage $before @($live) $wanted $install $false
 if($binding.status -cne 'PASS'){throw 'valid active version binding rejected'}
}else{
 $actual=Start-CanonicalRelayAfterFenceRelease
 if($actual -ne 4111 -or -not $script:launched){throw 'returned launcher PID rather than actual relay'}
}
'PASS'
''', values={"CA_BOOTSTRAP_MODE": mode}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_unknown_quoted_json_credentials_are_masked(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$Script:InstallationEvidenceSensitiveValues=@('known-synthetic-value')
$text='{"authorization":"Bearer synthetic-unregistered-value\\\"synthetic-escaped-value","credential":"synthetic-other-value","other":"kept"}'
$safe=Protect-InstallationText $text
if($safe.Contains('synthetic-unregistered-value') -or $safe.Contains('synthetic-other-value') -or $safe.Contains('synthetic-escaped-value')){throw 'unknown JSON credential value survived masking'}
if(-not $safe.Contains('kept')){throw 'unrelated evidence lost'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_real_relay_readback_rejects_stale_and_foreign_residents(tmp_path, engine):
    result = run_functions(tmp_path, SOURCE, ["Get-CanonicalFailureDetails"], r'''
$started=[DateTime]::UtcNow.AddSeconds(-1);$sha=('1'*40)
$exe=Join-Path $env:CA_CONTRACT_ROOT 'version\runtime\pythonw.exe';$line='"'+$exe+'" -I -B "'+(Join-Path $env:CA_CONTRACT_ROOT 'version\app\main.py')+'" --container-audit-user-relay'
$identity=[pscustomobject]@{executable=$exe;command=$line;source_commit=$sha;requires_status_identity=$true;operator_sid='S-1-5-21-111-222-333-1001'}
$caller=[pscustomobject]@{sid='S-1-5-21-111-222-333-1001';session_id=1;elevated=$true;integrity_level=12288}
foreach($case in @('valid','stale_hash','old_status','old_process','wrong_pid','old_commit','missing_commit','false_ordinary','string_retry','wrong_sid','wrong_session','elevated','high_integrity','wrong_argv')){
 $process=[pscustomobject]@{ProcessId=4111;ExecutablePath=$exe;CommandLine=$line;CreationDate=[DateTime]::UtcNow}
 $security=[pscustomobject]@{sid=$caller.sid;session_id=1;elevated=$false;integrity_level=8192}
 $status=[pscustomobject]@{report_version='container-audit-user-relay-v1';status='RUNNING';principal='current_user';persistent_retry=$true;process_id=4111;source_commit=$sha;ordinary_user=$true;updated_at=[DateTime]::UtcNow.ToString('o')}
 $previous='previous';$hash='fresh'
 switch($case){
  'stale_hash'{$hash=$previous};'old_status'{$status.updated_at=[DateTime]::UtcNow.AddMinutes(-5).ToString('o')}
  'old_process'{$process.CreationDate=[DateTime]::UtcNow.AddMinutes(-5)};'wrong_pid'{$status.process_id=3111}
  'old_commit'{$status.source_commit=('2'*40)};'missing_commit'{$status.PSObject.Properties.Remove('source_commit')}
  'false_ordinary'{$status.ordinary_user=$false};'string_retry'{$status.persistent_retry='false'}
  'wrong_sid'{$security.sid='S-1-5-21-111-222-333-1002'};'wrong_session'{$security.session_id=2}
  'elevated'{$security.elevated=$true};'high_integrity'{$security.integrity_level=12288}
  'wrong_argv'{$process.CommandLine+=' --unapproved-argument'}
 }
 $accepted=Test-BootstrapRelayReadback $identity $process $security $caller $status $started $previous $hash
 if($accepted -ne ($case -ceq 'valid')){throw ('real relay predicate violated '+$case)}
}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_real_canonical_timeout_preserves_status_and_never_returns_launcher(tmp_path, engine):
    names = re.findall(r"^function\s+([^\s(]+)", SOURCE.read_text(encoding="utf-8-sig"), re.M)
    result = run_functions(tmp_path, SOURCE, names, r'''
function Set-InstallationEvidenceAcl {}
$root=Initialize-InstallationEvidence (Join-Path $env:CA_CONTRACT_ROOT 'timeout') 'S-1-5-21-111-222-333-1001'
$relayPath=Join-Path $env:CA_CONTRACT_ROOT 'old-status.json'
$exe=Join-Path $env:CA_CONTRACT_ROOT 'runtime\pythonw.exe';$line='"'+$exe+'" -I -B main.py --container-audit-user-relay'
$identity=[pscustomobject]@{managed=$false;source_commit='';executable=$exe;command=$line;operator_sid='';requires_status_identity=$false}
$live=[pscustomobject]@{ProcessId=4111;ExecutablePath=$exe;CommandLine=$line;CreationDate=[DateTime]::UtcNow}
[IO.File]::WriteAllText($relayPath,(@{report_version='container-audit-user-relay-v1';status='RUNNING';principal='current_user';persistent_retry=$true;updated_at=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
$before=Get-FileSha256 $relayPath
function Relays {return @($live)}
function Get-CimInstance {return $live}
function Get-CanonicalRelaySecurity([int]$ProcessId){return [pscustomobject]@{sid='S-1-5-21-111-222-333-1001';session_id=1;elevated=($ProcessId -eq $PID);integrity_level=8192}}
$failed=$false;try{[void](Wait-CanonicalRelayReady $identity ([DateTime]::UtcNow) $before @() 1)}catch{$failed=$_.Exception.Message -ceq 'CANONICAL_RELAY_READY_TIMEOUT'}
if(-not $failed -or (Get-FileSha256 $relayPath) -cne $before){throw 'stale status caused success or original status was changed'}
$events=@(Get-Content -LiteralPath (Join-Path $root 'stages.jsonl')|ForEach-Object {$_|ConvertFrom-Json}|Where-Object {$_.event -ceq 'RESIDENT_RELAY_READY_TIMEOUT'})
if($events.Count -ne 1 -or $events[0].status_sha256 -cne $before -or $events[0].candidate_count -ne 1){throw 'timeout original status evidence missing'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr

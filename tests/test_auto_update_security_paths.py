"""Synthetic ACL checks of the native boundary, without native lifecycle calls."""
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("launch", ["absent", "present", "helper", "acl"])
def test_powershell_children_use_process_bypass(tmp_path, monkeypatch, launch):
    import auto_update as update
    from tools import install_protected_admin as admin

    commands = []

    def capture(command, **kwargs):
        commands.append(command)
        output = update.logon_task_xml(app_root=tmp_path, operator_sid="S-1-5-21-1-2-3-1001") if launch == "present" else "PASS"
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", capture)
    if launch == "absent":
        assert update.supported_tasks_absent(tmp_path)
    elif launch == "present":
        assert update.supported_task_present(tmp_path, "S-1-5-21-1-2-3-1001")
    elif launch == "helper":
        assert update.fixed_helper(tmp_path / "update-control", "Observe") == "PASS"
    else:
        assert admin._run_powershell("'PASS'", environment={}) == "PASS"
    command, = commands
    mode = "-File" if launch == "helper" else "-Command"
    assert command[command.index("-ExecutionPolicy"):command.index("-ExecutionPolicy") + 2] == ["-ExecutionPolicy", "Bypass"]
    assert command.index("-ExecutionPolicy") < command.index(mode)


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_identity_probe_uses_process_bypass(tmp_path, engine):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip("PowerShell engine unavailable")
    source = Path(__file__).resolve().parents[1] / "tools/resolve_windows_powershell.ps1"
    driver = tmp_path / "identity-arguments.ps1"
    driver.write_text(r'''param([string]$Source)
$tokens=$null;$errors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Source parse error'}
$calls=@($tree.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.CommandElements[0].Extent.Text -ceq '$fullPath'},$true))
if($calls.Count -ne 1){throw 'Identity probe is not unique'}
$arguments=@($calls[0].CommandElements | ForEach-Object {$_.Extent.Text})
$policy=[Array]::IndexOf($arguments,'-ExecutionPolicy')
if($policy -lt 0 -or $arguments[$policy+1] -cne 'Bypass' -or $policy -ge [Array]::IndexOf($arguments,'-Command')){throw 'Identity probe policy is missing'}
'PASS'
''', encoding="utf-8-sig")
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver), "-Source", str(source)], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "PASS"


@pytest.mark.parametrize("policy,accepted", [("previous", True), ("bypass", True), ("wrong", False), ("extra", False)])
def test_task_observation_accepts_only_exact_previous_or_bypass_action(tmp_path, monkeypatch, policy, accepted):
    import auto_update as update
    import xml.etree.ElementTree as xml

    sid = "S-1-5-21-1-2-3-1001"
    task = xml.fromstring(update.logon_task_xml(app_root=tmp_path, operator_sid=sid))
    argument = task.find("{*}Actions/{*}Exec/{*}Arguments")
    if policy == "previous":
        argument.text = argument.text.replace(" -ExecutionPolicy Bypass -File ", " -File ", 1)
    elif policy == "wrong":
        argument.text = argument.text.replace("Bypass", "Unrestricted", 1)
    elif policy == "extra":
        argument.text += " -Unexpected"
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=xml.tostring(task, encoding="unicode"), stderr=""))
    assert update.supported_task_present(tmp_path, sid) is accepted


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
@pytest.mark.parametrize("consumer", ["identity", "removal"])
@pytest.mark.parametrize("policy", ["previous", "bypass", "wrong", "extra"])
def test_installer_task_consumers_preserve_exact_previous_action(tmp_path, engine, consumer, policy):
    import auto_update as update
    from tests.powershell_contracts import run_functions

    root = Path(r"E:\synthetic\current")
    sid = "S-1-5-21-1-2-3-1001"
    source = Path(__file__).resolve().parents[1] / "INSTALL_THIS_PC.ps1"
    expected = tmp_path / "expected.xml"
    expected.write_text(update.logon_task_xml(app_root=root, operator_sid=sid), encoding="utf-8")
    result = run_functions(tmp_path, source, ["Test-ContainerStartupUpdateTaskIdentity", "Resolve-ContainerRemovalTaskSid", "Get-ContainerRemovalTaskNames"], r'''
$root='E:\synthetic\current';$sid='S-1-5-21-1-2-3-1001'
[xml]$expected=[IO.File]::ReadAllText($env:CA_POLICY_XML)
[xml]$actual=$expected.CloneNode($true)
$arguments=[string]$actual.Task.Actions.Exec.Arguments
switch($env:CA_POLICY){
 'previous' {$arguments=$arguments.Replace(' -ExecutionPolicy Bypass -File ',' -File ')}
 'wrong' {$arguments=$arguments.Replace('Bypass','Unrestricted')}
 'extra' {$arguments+=' -Unexpected'}
}
$actual.Task.Actions.Exec.Arguments=$arguments
$before=$actual.OuterXml
function ConvertTo-BootstrapPrincipalSid([string]$Value){return $Value}
function Test-SamePath([string]$A,[string]$B){return $A.Equals($B,[StringComparison]::OrdinalIgnoreCase)}
$accepted=$false
if($env:CA_POLICY_CONSUMER -ceq 'identity'){
 $accepted=Test-ContainerStartupUpdateTaskIdentity $actual $expected $sid
}else{
 $task=[pscustomobject]@{Name=$env:CA_POLICY_TASK;Xml=$actual.OuterXml}
 $folder=[pscustomobject]@{Task=$task}
 $folder|Add-Member ScriptMethod GetTasks {param($flags) return $this.Task}
 try{$accepted=$env:CA_POLICY_TASK -cin @(Get-ContainerRemovalTaskNames $folder $root)}catch{if($_.Exception.Message -cne 'REMOVAL_TASK_IDENTITY_UNKNOWN'){throw}}
}
if($accepted -ne ($env:CA_POLICY -cin @('previous','bypass'))){throw 'Task ownership differs'}
if($actual.OuterXml -cne $before){throw 'Original task XML changed'}
'PASS'
''', engine=engine, values={"CA_POLICY_XML": str(expected), "CA_POLICY": policy, "CA_POLICY_CONSUMER": consumer, "CA_POLICY_TASK": update.task_name(root, sid)})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("relative,function", [
    ("INSTALL_THIS_PC.ps1", "Assert-ProtectedCodeAncestors"),
    ("tools/apply_prepared_update.ps1", "Assert-Protected"),
])
@pytest.mark.parametrize("defect", ["owner", "delete-child", "write-dacl", "reparse", "leaf-write", "safe"])
def test_update_boundary_checks_synthetic_path_chain(tmp_path, relative, function, defect):
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell required")
    repository = Path(__file__).resolve().parents[1]
    script = tmp_path / "check-acl.ps1"
    script.write_text(r'''param([string]$Source,[string]$Function,[string]$Defect)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Source parse error' }
$ownerSource=if((Split-Path -Leaf $Source) -ceq 'INSTALL_THIS_PC.ps1'){Join-Path (Split-Path -Parent $Source) 'tools\bootstrap_integrity.ps1'}else{$Source}
$ownerTree=[Management.Automation.Language.Parser]::ParseFile($ownerSource,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Owner source parse error'}
$ownerDefinition=$ownerTree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-BootstrapPrivilegedOwnerSid'},$true)
if($null -ne $ownerDefinition){Invoke-Expression $ownerDefinition.Extent.Text}
$definition=$tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Function},$true)
if ($null -eq $definition) { throw 'Required boundary function absent' }
Invoke-Expression $definition.Extent.Text
$nodes=@{}
$paths=@('C:\','C:\Trusted','C:\Trusted\Apps','C:\Trusted\Apps\IW','C:\Trusted\Apps\IW\current','C:\Trusted\Apps\IW\current\tools','C:\Trusted\Apps\IW\current\tools\helper.ps1')
foreach($path in $paths) {
    $parent=if($path -ceq 'C:\') { '' } else { [IO.Path]::GetDirectoryName($path) }
    $parentNode=if($parent -and $nodes.ContainsKey($parent)){$nodes[$parent]}else{$null}
    $nodes[$path]=[pscustomobject]@{FullName=$path;Attributes=[IO.FileAttributes]::Normal;PSIsContainer=($path -notlike '*.ps1');Parent=$parentNode}
}
if ($Defect -eq 'reparse') { $nodes['C:\Trusted'].Attributes=[IO.FileAttributes]::ReparsePoint }
function Get-Item { param([string]$LiteralPath,[string]$ErrorAction,[switch]$Force) return $nodes[$LiteralPath] }
function Test-Path { param([string]$LiteralPath) return $nodes.ContainsKey($LiteralPath) }
function Get-Acl {
    param([string]$LiteralPath,[string]$ErrorAction)
    $unsafe=$LiteralPath -ceq 'C:\Trusted'
    $owner=if($unsafe -and $Defect -eq 'owner'){'S-1-5-21-11-22-33-1001'}else{'S-1-5-32-544'}
    $rights=if($unsafe -and $Defect -eq 'delete-child'){0x40}elseif($unsafe -and $Defect -eq 'write-dacl'){0x40000}elseif($LiteralPath -like '*.ps1' -and $Defect -eq 'leaf-write'){2}else{0}
    $acl=[pscustomobject]@{OwnerValue=$owner;Rules=@([pscustomobject]@{AccessControlType='Allow';IdentityReference=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');FileSystemRights=$rights;PropagationFlags=[Security.AccessControl.PropagationFlags]::None})}
    $acl | Add-Member ScriptMethod GetOwner {param($type) [Security.Principal.SecurityIdentifier]::new($this.OwnerValue)}
    $acl | Add-Member ScriptMethod GetAccessRules {param($explicit,$inherited,$type) $this.Rules}
    return $acl
}
try {
    & $Function $paths[-1]
    if($Defect -ne 'safe') { throw 'Unsafe chain was accepted' }
} catch {
    if($Defect -eq 'safe' -or $_.Exception.Message -eq 'Unsafe chain was accepted') { throw }
}
'PASS'
''', encoding="utf-8")
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-File", str(script),
                             "-Source", str(repository / relative), "-Function", function, "-Defect", defect],
                            capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS"


def test_native_boundary_refuses_before_loading_an_untrusted_helper(tmp_path):
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell required")
    repository = Path(__file__).resolve().parents[1]
    tools = tmp_path / "current" / "tools"
    tools.mkdir(parents=True)
    script = tools / "apply_prepared_update.ps1"
    script.write_bytes((repository / "tools/apply_prepared_update.ps1").read_bytes())
    (tools / "bootstrap_integrity.ps1").write_text("throw 'UNTRUSTED_HELPER_LOADED'", encoding="utf-8")
    wrapper = tmp_path / "preflight.ps1"
    wrapper.write_text(r'''param([string]$Script,[string]$Root)
$ErrorActionPreference='Stop'
function Get-Acl {
    param([string]$LiteralPath,[string]$ErrorAction)
    $acl=[pscustomobject]@{}
    $acl | Add-Member ScriptMethod GetOwner {param($type) [Security.Principal.SecurityIdentifier]::new('S-1-5-21-11-22-33-1001')}
    $acl | Add-Member ScriptMethod GetAccessRules {param($explicit,$inherited,$type) @()}
    return $acl
}
try { & $Script -InstallRoot $Root -Mode Authority; throw 'Boundary absent' }
catch { if($_.Exception.Message -cne 'Update storage owner is not privileged.') { throw } }
'PASS'
''', encoding="utf-8")
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-File", str(wrapper),
         "-Script", str(script), "-Root", str(tools.parent)],
        capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS"


@pytest.mark.parametrize("record", ["trial.json", "ready.json"])
def test_readiness_io_error_keeps_normal_rollback_and_original_proof(monkeypatch, tmp_path, record):
    import auto_update as updates
    from test_auto_update import test_engine_candidate_exit_selects_generation_compatible_code_without_reverting_data

    original = updates.read_json
    write = updates.write_json_durable
    def proof(path, value):
        write(path, value)
        if path.name == "trial.json" and record == "ready.json":
            # An incomplete candidate proof is unconfirmed and must be preserved.
            write(path.with_name("ready.json"), {**value, "sha": "2" * 40})
    monkeypatch.setattr(updates, "write_json_durable", proof)
    import time
    ticks = iter(range(0, 10000, 10))
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    denied = []
    def contested(path, **kwargs):
        journal = tmp_path / "managed/update-control/transition.json"
        if path.name == record and journal.exists() and not denied:
            if original(journal)["phase"] == "APPLIED_PENDING_READY":
                denied.append(path.read_bytes())
                raise OSError("synthetic sharing contention")
        return original(path, **kwargs)
    monkeypatch.setattr(updates, "read_json", contested)
    test_engine_candidate_exit_selects_generation_compatible_code_without_reverting_data(monkeypatch, tmp_path, "unchanged")
    assert denied
    assert (tmp_path / "operator/updates" / record).read_bytes() == denied[0]
    state = original(tmp_path / "managed/update-control/transition.json")
    assert state["last_ready_error"] == "OSError"


@pytest.mark.parametrize("denials", [1, 2, 3])
def test_atomic_state_read_retries_only_transient_denial(monkeypatch, tmp_path, denials):
    import auto_update as updates

    path = tmp_path / "active.json"
    path.write_text('{"sha":"original"}', encoding="utf-8")
    original = Path.open
    attempts = []
    def contested(self, *args, **kwargs):
        if self == path:
            attempts.append(1)
            if len(attempts) <= denials:
                raise PermissionError("synthetic atomic replacement")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, "open", contested)
    if denials == 3:
        with pytest.raises(PermissionError):
            updates.read_json(path)
    else:
        assert updates.read_json(path) == {"sha": "original"}
    assert len(attempts) == min(denials + 1, 3)


def test_atomic_state_read_keeps_malformed_record_failure(tmp_path):
    import auto_update as updates

    path = tmp_path / "active.json"
    path.write_text('{"sha":"old","sha":"new"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate update record field"):
        updates.read_json(path)
    assert path.read_text(encoding="utf-8") == '{"sha":"old","sha":"new"}'

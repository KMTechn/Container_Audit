"""Synthetic ACL checks of the native boundary, without native lifecycle calls."""
from pathlib import Path
import shutil
import subprocess

import pytest


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
    from test_auto_update import test_engine_candidate_exit_restarts_previous_version_without_reverting_data

    original = updates.read_json
    denied = []
    def contested(path, **kwargs):
        journal = tmp_path / "managed/update-control/transition.json"
        if path.name == record and journal.exists() and not denied:
            if original(journal)["phase"] == "ROLLBACK_PENDING_READY":
                denied.append(path.read_bytes())
                raise OSError("synthetic sharing contention")
        return original(path, **kwargs)
    monkeypatch.setattr(updates, "read_json", contested)
    test_engine_candidate_exit_restarts_previous_version_without_reverting_data(monkeypatch, tmp_path)
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



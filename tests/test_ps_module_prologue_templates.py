"""Parse real scripts and resolve their OS cmdlets under all three engines."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
KINDS = [
    "INSTALL_CANONICAL_PORTABLE.ps1", "INSTALL_THIS_PC.ps1", "tools/apply_prepared_update.ps1",
    "tools/bootstrap_integrity.ps1", "tools/container_writer_fence.ps1",
    "tools/container_writer_session.ps1", "tools/provision_protected_admin_acl.ps1",
    "kmtech_shared/powershell/portable.ps1",
    "reader", "apply-acl", "verify-acl", "acl-identity", "acl-compare", "task-present",
    "register-password", "register-system",
    "transport-bootstrap", "elevation-wrapper", "normal-producer-wrapper",
]
COMMANDS = r"\b(?:Convert(?:To|From)-Json|Get-Content|Get-Date|New-TimeSpan|New-Object|Out-Null|Get-FileHash|Get-Acl|Set-Acl|Get-AuthenticodeSignature|Get-CimInstance|Select-Object)\b"
BOOTSTRAP_TEMPLATES = {
    "transport-bootstrap": "New-InstallationMemoryTransport",
    "elevation-wrapper": "Get-InstallationElevationWrapperSource",
    "normal-producer-wrapper": "Get-InstallationNormalProducerWrapperSource",
}


def _render(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_render(value) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _render(node.left) + _render(node.right)
    return "fixture"


def _script(kind):
    if kind.endswith(".ps1"):
        return (ROOT / kind).read_bytes().decode("utf-8-sig")
    if kind in BOOTSTRAP_TEMPLATES:
        source = (ROOT / "tools/bootstrap_integrity.ps1").read_bytes().decode("utf-8-sig")
        opening = "(" if kind == "transport-bootstrap" else " {"
        owner = source.split("function " + BOOTSTRAP_TEMPLATES[kind] + opening, 1)[1]
        owner = owner.split("\n}\n\nfunction ", 1)[0]
        imports = re.findall(r'"(Import-Module [^"\n]+)"', owner)
        assert len(imports) == 2
        prefix = "".join(line.replace("`n", "\n").replace("`$", "$") for line in imports)
        body = owner.split("@'\n", 1)[1].split("\n'@", 1)[0]
        if kind != "transport-bootstrap":
            verified = source.split("function Get-InstallationVerifiedScript {", 1)[1].split("\n}\n", 1)[0]
            prefix += "function Get-InstallationVerifiedScript {" + verified + "\n}\n"
        return prefix + body
    path, function, variable = {
        "reader": ("tools/install_protected_admin.py", "_resolve_reader_sid", "script"),
        "apply-acl": ("tools/install_protected_admin.py", "_apply_exact_acl", "script"),
        "verify-acl": ("tools/install_protected_admin.py", "_verify_exact_acl", "script"),
        "acl-identity": ("current_user_onboarding.py", "_windows_acl_identity", "command"),
        "acl-compare": ("current_user_onboarding.py", "_replacement_identities_match", "command"),
        "task-present": ("auto_update.py", "supported_task_present", "script"),
        "register-password": ("tools/direct_sync_relay_install_pack.py", "_stored_password_task_register_command", "script"),
        "register-system": ("tools/direct_sync_relay_install_pack.py", "_system_service_task_register_command", "script"),
    }[kind]
    tree = ast.parse((ROOT / path).read_bytes())
    owner = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function)
    value = next(node.value for node in ast.walk(owner) if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == variable for target in node.targets))
    if isinstance(value, ast.Call):
        return "\n".join(_render(item) for item in value.args[0].elts)
    return _render(value)


@pytest.mark.parametrize("kind", KINDS)
def test_literal_prologue_precedes_first_os_module_command(kind):
    prologue = (ROOT / "kmtech_shared/powershell/ps51_module_prologue.ps1").read_bytes()
    assert hashlib.sha256(prologue).hexdigest() == "9c5e083b8e332573f3368be3e9592a2e2409aa89891e15942026361be17d0b71"
    source = _script(kind).encode("utf-8")
    assert b"\xef\xbb\xbf" not in source, "UTF-8 BOM must remain only at the original file start"
    assert source.count(prologue) == 1
    before, after = source.split(prologue)
    assert not re.search(COMMANDS, before.decode("utf-8"))
    assert re.search(COMMANDS, after.decode("utf-8"))


def _run_ps(tmp_path, script, mode, environment=None):
    child = tmp_path / "child.ps1"
    child.write_bytes(script.encode("utf-8-sig"))
    native = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    env = os.environ.copy()
    env.update(environment or {})
    env["TEMP"] = env["TMP"] = str(tmp_path)
    env["PSModuleAnalysisCachePath"] = str(tmp_path / "module-cache")
    env["PSModulePath"] = str(native.parent / "Modules")
    args = [str(native), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-File", str(child)]
    if mode == "ps7":
        executable = shutil.which("pwsh.exe")
        assert executable, "Required PowerShell 7 is unavailable"
        args[0] = executable
    if mode == "inherited":
        executable = shutil.which("pwsh.exe")
        assert executable, "Required PS7 parent is unavailable"
        parent = tmp_path / "parent.ps1"
        parent.write_bytes(r'''param([string]$Child,[string]$Probe)
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
$start=[Diagnostics.ProcessStartInfo]::new()
$start.FileName=$Child;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
foreach($arg in @('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-File',$Probe)){$start.ArgumentList.Add($arg)}
$p=[Diagnostics.Process]::Start($start)
$output=$p.StandardOutput.ReadToEnd();$failure=$p.StandardError.ReadToEnd()
$p.WaitForExit();[Console]::Out.Write($output);[Console]::Error.Write($failure);exit $p.ExitCode
'''.encode("utf-8"))
        args = [executable, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-File",
                str(parent), "-Child", str(native), "-Probe", str(child)]
    return subprocess.run(args, env=env, capture_output=True, text=True,
                          creationflags=subprocess.CREATE_NO_WINDOW)


@pytest.mark.parametrize("mode", ["clean51", "inherited", "ps7"])
@pytest.mark.parametrize("kind", KINDS)
def test_each_script_parses_and_its_imports_resolve_os_cmdlets(tmp_path, kind, mode):
    target = tmp_path / "target.ps1"
    target.write_bytes(_script(kind).encode("utf-8-sig"))
    literal = str(target).replace("'", "''")
    driver = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('TARGET',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'script parsing failed'}
$imports=@($ast.EndBlock.Statements | Where-Object {
 $_ -is [Management.Automation.Language.PipelineAst] -and $_.PipelineElements[0] -is [Management.Automation.Language.CommandAst] -and $_.PipelineElements[0].GetCommandName() -ceq 'Import-Module'
})
if($imports.Count -ne 2){throw 'script imports differ'}
foreach($statement in $imports){Invoke-Expression $statement.Extent.Text}
foreach($name in @('Get-FileHash','Get-Acl','Set-Acl','Get-AuthenticodeSignature','Get-Content','ConvertFrom-Json','ConvertTo-Json')){
 $command=Get-Command $name -ErrorAction Stop
 if($command.ModuleName -cnotin @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Management')){throw 'unexpected OS module'}
}
[Console]::Out.Write('PASS_PARSED_AND_RESOLVED')
'''.replace("TARGET", literal)
    result = _run_ps(tmp_path, driver, mode)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "PASS_PARSED_AND_RESOLVED"


def test_actual_bootstrap_pin_lookup_under_ps7_parent(tmp_path):
    literal = str(ROOT).replace("'", "''")
    result = _run_ps(tmp_path, f"$ErrorActionPreference='Stop'\n. '{literal}/tools/bootstrap_integrity.ps1'\n"
                     f"$leaf=Get-BootstrapSharedPortableLeaf '{literal}'\n. $leaf\n"
                     "[Console]::Out.Write('PASS_PINNED_BOOTSTRAP')\n", "inherited")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "PASS_PINNED_BOOTSTRAP"


@pytest.mark.parametrize("mode", ["clean51", "inherited", "ps7"])
def test_actual_writer_fence_library_load_retains_strict_mode(tmp_path, mode):
    literal = str(ROOT / "tools/container_writer_fence.ps1").replace("'", "''")
    result = _run_ps(tmp_path, f"$ErrorActionPreference='Stop'\n. '{literal}'\n" + r'''
if($Script:ContainerWriterFenceAppId -cne 'container_audit'){throw 'fence library differs'}
$strict=$false
try{$null=$UnassignedFenceStrictModeProbe}catch [Management.Automation.RuntimeException]{$strict=$true}
if(-not $strict){throw 'fence StrictMode was not set'}
[Console]::Out.Write('PASS_ACTUAL_FENCE_LIBRARY')
''', mode)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "PASS_ACTUAL_FENCE_LIBRARY"


@pytest.mark.parametrize("kind", BOOTSTRAP_TEMPLATES)
def test_bootstrap_child_template_matches_actual_constructor(tmp_path, kind):
    literal = str(ROOT / "tools/bootstrap_integrity.ps1").replace("'", "''")
    expected = hashlib.sha256(_script(kind).encode("utf-8")).hexdigest()
    function = BOOTSTRAP_TEMPLATES[kind]
    driver = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('SOURCE',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'bootstrap parsing failed'}
$owner=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'FUNCTION'},$true))[0]
if('FUNCTION' -ceq 'New-InstallationMemoryTransport'){
 $assignments=@($owner.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$bootstrap'},$true))
 if($assignments.Count -ne 3){throw 'transport assignments differ'}
 Invoke-Expression $assignments[0].Extent.Text
 Invoke-Expression $assignments[1].Extent.Text
 $source=$bootstrap
}else{
 $verified=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-InstallationVerifiedScript'},$true))[0]
 Invoke-Expression $verified.Extent.Text
 Invoke-Expression $owner.Extent.Text
 $source=& 'FUNCTION'
}
$sha=[Security.Cryptography.SHA256]::Create()
try{$actual=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($source)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
if($actual -cne 'EXPECTED'){throw 'emitted template differs from static fixture'}
[Console]::Out.Write('PASS_ACTUAL_TEMPLATE')
'''.replace("SOURCE", literal).replace("FUNCTION", function).replace("EXPECTED", expected)
    result = _run_ps(tmp_path, driver, "clean51")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "PASS_ACTUAL_TEMPLATE"


def test_actual_acl_templates_under_ps7_parent_preserve_rejection(tmp_path):
    target = tmp_path / "synthetic-acl.txt"
    target.write_bytes(b"synthetic")
    prefix = ("$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
              "$env:KMTECH_PROTECTED_ADMIN_ACL_SDDL='D:PAI(A;;FA;;;'+$sid+')'\n")
    environment = {"KMTECH_PROTECTED_ADMIN_ACL_TARGET": str(target)}
    applied = _run_ps(tmp_path, prefix + _script("apply-acl"), "inherited", environment)
    assert applied.returncode == 0, applied.stderr
    verified = _run_ps(tmp_path, prefix + _script("verify-acl"), "inherited", environment)
    assert verified.returncode == 0, verified.stderr
    drift = prefix.replace(";;FA;;;", ";;FR;;;")
    refused = _run_ps(tmp_path, drift + _script("verify-acl"), "inherited", environment)
    assert refused.returncode == 1
    assert refused.stderr == "exact ACL verification failed"


def test_actual_json_transport_under_ps7_parent_keeps_byte_pin_refusal(tmp_path):
    code = tmp_path / "owned-code.ps1"
    data = tmp_path / "owned-args.json"
    values = ["한글", "quoted value", ""]
    code.write_bytes(b"[Console]::Out.Write((ConvertTo-Json -InputObject @($args) -Compress))")
    data.write_bytes(json.dumps(values, ensure_ascii=False).encode("utf-8"))
    script = _script("transport-bootstrap")
    for name, path in (("code", code), ("data", data)):
        script = script.replace("@@" + name + "-path@@", str(path).replace("'", "''"))
        script = script.replace("@@" + name + "-sha@@", hashlib.sha256(path.read_bytes()).hexdigest())
    accepted = _run_ps(tmp_path, script, "inherited")
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(accepted.stdout) == values
    data.write_bytes(b"[]")
    refused = _run_ps(tmp_path, script, "inherited")
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert refused.stderr.strip() == "Installation launcher transport rejected."

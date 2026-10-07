"""Native transport contracts, without elevation or installer entrypoints."""
from pathlib import Path
import base64
import hashlib
import json
import os
import shutil
import subprocess

import pytest

from tests.powershell_contracts import run_functions, run_powershell

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "tools/bootstrap_integrity.ps1"
ENGINES = ("powershell.exe", "pwsh.exe")


def prepare(tmp_path, engine, source, arguments):
    # Only the owned temporary directory is admitted; no native known folder,
    # registry, task, credential or elevation APIs are reached.
    (tmp_path / "code.txt").write_text(source, encoding="utf-8")
    (tmp_path / "args.json").write_text(json.dumps(arguments), encoding="utf-8")
    result = run_functions(tmp_path, LIBRARY, ["ConvertTo-InstallationMemoryCommand"], r'''
. $env:CA_CONTRACT_SOURCE
function Assert-InstallationEvidenceWriteRoot {param($Root)
 if([IO.Path]::GetFullPath($Root) -cne [IO.Path]::GetFullPath($env:CA_CONTRACT_ROOT)){throw 'outside fixture'}
}
$source=[IO.File]::ReadAllText((Join-Path $env:CA_CONTRACT_ROOT 'code.txt'))
$parsed=[IO.File]::ReadAllText((Join-Path $env:CA_CONTRACT_ROOT 'args.json'))|ConvertFrom-Json
$values=[string[]]@($parsed)
$transport=New-InstallationMemoryTransport $source $values $env:CA_CONTRACT_ROOT
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'transport.json'),($transport|ConvertTo-Json -Depth 5))
'PREPARED'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads((tmp_path / "transport.json").read_text(encoding="utf-8-sig"))


def child(engine, encoded):
    environment = dict(os.environ)
    if engine == "powershell.exe":
        environment["PSModulePath"] = str(Path(shutil.which(engine)).parent / "Modules")
    completed = subprocess.run([shutil.which(engine), "-NoLogo", "-NoProfile", "-NonInteractive",
                           "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
                          capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, env=environment)
    # Pytest failures must not expand the private encoded command in logs.
    completed.args = [engine, "-EncodedCommand", "[private transport]"]
    return completed


def grant_fixture_owner_write(tmp_path, paths, engine):
    # Model the file owner changing its DACL before verification. No owner,
    # privilege, host security settings or paths outside the fixture change.
    driver = tmp_path / "grant-fixture-write.ps1"
    driver.write_text(r'''
$ErrorActionPreference='Stop'
foreach($path in $args){
 $acl=Get-Acl -LiteralPath $path
 if(-not $acl.AreAccessRulesProtected){throw 'transport DACL was not protected'}
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
  [Security.Principal.WindowsIdentity]::GetCurrent().User,'Modify','Allow'))
 if($PSVersionTable.PSEdition -ceq 'Desktop'){[IO.File]::SetAccessControl($path,$acl)}
 else{[IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($path),$acl)}
}
''', encoding="utf-8-sig")
    result = run_powershell([shutil.which(engine), "-NoProfile", "-NonInteractive", "-File", str(driver), *map(str, paths)])
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("engine", ENGINES)
def test_long_argv_is_bound_and_preserves_unicode_empty_quote_and_order(tmp_path, engine):
    user_root = tmp_path / ("u" * 20)
    tmp_path = user_root / ("p" * (238 - len(str(user_root)) - 1))
    tmp_path.mkdir(parents=True)
    assert len(str(tmp_path)) == 238
    values = ["", "한글", "a'b", 'a"b', "-NamedSwitch"] + ["x" * 259] * 45
    transport = prepare(tmp_path, engine,
                        "if($args.Count -ne 50 -or $args[0] -cne '' -or $args[1] -cne '한글' "
                        "-or $args[2] -cne \"a'b\" -or $args[3] -cne 'a\"b' "
                        "-or $args[4] -cne '-NamedSwitch'){exit 9};exit 0", values)
    assert all(len(path) == 259 for path in transport["Paths"])
    assert len(transport["Encoded"]) + 200 < 16000
    result = child(engine, transport["Encoded"])
    assert result.returncode == 0, result.stderr.decode(errors="replace")


@pytest.mark.parametrize("engine", ENGINES)
def test_empty_argument_array_does_not_become_a_null_argument(tmp_path, engine):
    transport = prepare(tmp_path, engine, "if($args.Count){exit 8};exit 0", [])
    result = child(engine, transport["Encoded"])
    assert result.returncode == 0, result.stderr.decode(errors="replace")


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("target", (0, 1))
@pytest.mark.parametrize("fault", ("byte", "missing", "swap", "leaf", "ancestor"))
def test_preverification_fault_never_executes_source(tmp_path, engine, target, fault):
    marker = tmp_path / "executed.txt"
    source = "[IO.File]::WriteAllText('%s','executed')" % str(marker).replace("'", "''")
    transport = prepare(tmp_path, engine, source, ["valid"])
    path = Path(transport["Paths"][target])
    grant_fixture_owner_write(tmp_path, transport["Paths"], engine)
    if fault == "byte":
        content = bytearray(path.read_bytes())
        content[-1] ^= 1
        path.write_bytes(content)
    elif fault == "missing":
        path.unlink()
    elif fault == "swap":
        substitute = tmp_path / "substitute"
        substitute.write_bytes(b"different")
        os.replace(substitute, path)
    else:
        # Native junctions require no symlink privilege. Leaf and ancestor
        # reparse cases use separate paths, leaving all originals preserved.
        original = tmp_path / "original"
        original.mkdir()
        shutil.copyfile(path, original / path.name)
        junction = tmp_path / "junction"
        made = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(original)],
                              capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert made.returncode == 0
        linked = junction if fault == "leaf" else junction / path.name
        decoded = base64.b64decode(transport["Encoded"]).decode("utf-16-le")
        transport["Encoded"] = base64.b64encode(decoded.replace(str(path), str(linked)).encode("utf-16-le")).decode("ascii")
    result = child(engine, transport["Encoded"])
    assert result.returncode == 1
    assert not marker.exists()


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("target", (0, 1))
@pytest.mark.parametrize("operation", ("write", "replace"))
def test_verified_handle_keeps_original_bytes_during_write_and_replace(tmp_path, engine, target, operation):
    # The pinned script itself attempts mutation after both handles opened.
    # Paths are supplied as argv, so preparation needs no assumed filenames.
    source = r'''
$denied=$false
try{if($args[2] -ceq 'write'){[IO.File]::WriteAllText($args[0],'bad')}
else{[IO.File]::Delete($args[0]);[IO.File]::Move($args[1],$args[0])}}catch [IO.IOException]{$denied=$true}
if($denied -ne ($args[2] -ceq 'write')){exit 8};[Console]::Out.WriteLine('ORIGINAL_BYTES');exit 0
'''
    # A deterministic path supplied by the test targets the transport opened
    # by its production bootstrap, without changing its verified code buffer.
    transport = prepare(tmp_path, engine, source, ["PLACEHOLDER", str(tmp_path / "replace"), operation])
    grant_fixture_owner_write(tmp_path, transport["Paths"], engine)
    path = Path(transport["Paths"][target])
    payload = Path(transport["Paths"][1])
    payload.write_text(json.dumps([str(path), str(tmp_path / "replace"), operation]), encoding="utf-8")
    decoded = base64.b64decode(transport["Encoded"]).decode("utf-16-le")
    decoded = decoded.replace(transport["PayloadSha256"], hashlib.sha256(payload.read_bytes()).hexdigest())
    (tmp_path / "replace").write_bytes(b"bad")
    result = child(engine, base64.b64encode(decoded.encode("utf-16-le")).decode("ascii"))
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert b"ORIGINAL_BYTES" in result.stdout
    if operation == "replace":
        assert path.read_bytes() == b"bad"


@pytest.mark.parametrize("engine", ENGINES)
def test_caller_bound_and_original_secondary_budget(tmp_path, engine):
    result = run_functions(tmp_path, LIBRARY, ["ConvertTo-InstallationMemoryCommand"], r'''
. $env:CA_CONTRACT_SOURCE
function Assert-InstallationEvidenceWriteRoot {}
$rejected=$false
try{Assert-InstallationMemoryCommandBound ('x'*16000)}catch{$rejected=$true}
if(-not $rejected){throw 'caller accepted an oversized command'}
$rejected=$false
try{ConvertTo-InstallationMemoryCommand ('x'*20000) @()}catch{$rejected=$true}
if(-not $rejected){throw 'original secondary budget changed'}
$transport=New-InstallationMemoryTransport 'exit 0' @() $env:CA_CONTRACT_ROOT
Remove-InstallationMemoryTransport $transport
foreach($p in $transport.Paths){if([IO.File]::Exists($p)){throw 'transport retained'}}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("fault", ("valid", "helper", "library", "unknown-switch", "missing-value"))
def test_original_helper_library_pins_named_switch_and_filename_survive_transport(tmp_path, engine, fault):
    library = tmp_path / "library.ps1"
    helper = tmp_path / "helper.ps1"
    library.write_text("$Script:FixtureLibraryLoaded=$true", encoding="utf-8-sig")
    helper.write_text(r'''
param([switch]$NamedSwitch,[string]$Value)
if(-not $Script:FixtureLibraryLoaded -or -not $NamedSwitch -or $Value -cne '한글' -or
 $Script:InstallationPinnedBootstrapLibrary.Ast.Extent.File -cne (Join-Path $PSScriptRoot 'library.ps1')){exit 8}
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'result.json'),(@{file=$PSCommandPath;root=$PSScriptRoot}|ConvertTo-Json))
''', encoding="utf-8-sig")
    values = [str(helper), hashlib.sha256(helper.read_bytes()).hexdigest(),
              str(library), hashlib.sha256(library.read_bytes()).hexdigest(),
              str(tmp_path), "-NamedSwitch", "-Value", "한글"]
    result = run_functions(tmp_path, LIBRARY, ["Get-InstallationHelperMemorySource"], r'''
. $env:CA_CONTRACT_SOURCE
$source='function Get-InstallationVerifiedScript {'+${function:Get-InstallationVerifiedScript}.ToString()+"}`n"+(Get-InstallationHelperMemorySource)
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'helper-source.txt'),$source,[Text.UTF8Encoding]::new($true))
''', engine=engine)
    assert result.returncode == 0, result.stderr
    transport = prepare(tmp_path, engine, (tmp_path / "helper-source.txt").read_text(encoding="utf-8"), values)
    if fault in ("helper", "library"):
        path = helper if fault == "helper" else library
        content = bytearray(path.read_bytes())
        content[-1] ^= 1
        path.write_bytes(content)
    elif fault in ("unknown-switch", "missing-value"):
        grant_fixture_owner_write(tmp_path, transport["Paths"], engine)
        payload = Path(transport["Paths"][1])
        changed = values[:-1] if fault == "missing-value" else values + ["-UnknownSwitch"]
        payload.write_text(json.dumps(changed), encoding="utf-8")
        decoded = base64.b64decode(transport["Encoded"]).decode("utf-16-le")
        decoded = decoded.replace(transport["PayloadSha256"], hashlib.sha256(payload.read_bytes()).hexdigest())
        transport["Encoded"] = base64.b64encode(decoded.encode("utf-16-le")).decode("ascii")
    result = child(engine, transport["Encoded"])
    marker = tmp_path / "result.json"
    if fault == "valid":
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        observed = json.loads(marker.read_bytes())
        assert observed["file"] == str(helper)
        assert observed["root"] == str(tmp_path)
    else:
        assert result.returncode == 1
        assert not marker.exists()


@pytest.mark.parametrize("engine", ENGINES)
def test_new_files_are_private_even_when_parent_denies_take_ownership(tmp_path, engine):
    result = run_functions(tmp_path, LIBRARY, ["ConvertTo-InstallationMemoryCommand"], r'''
. $env:CA_CONTRACT_SOURCE
function Assert-InstallationEvidenceWriteRoot {}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$parent=Get-Acl -LiteralPath $env:CA_CONTRACT_ROOT
$parentDacl=[Security.AccessControl.DirectorySecurity]::new()
$parentDacl.SetSecurityDescriptorSddlForm($parent.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access),[Security.AccessControl.AccessControlSections]::Access)
$parentDacl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'TakeOwnership','ContainerInherit,ObjectInherit','None','Deny'))
if($PSVersionTable.PSEdition -ceq 'Desktop'){[IO.Directory]::SetAccessControl($env:CA_CONTRACT_ROOT,$parentDacl)}
else{[IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($env:CA_CONTRACT_ROOT),$parentDacl)}
$t=New-InstallationMemoryTransport 'exit 0' @() $env:CA_CONTRACT_ROOT
try{
 foreach($p in $t.Paths){
  $acl=Get-Acl -LiteralPath $p
  if(-not $acl.AreAccessRulesProtected){throw 'transport is not private'}
  foreach($rule in $acl.Access){
   if($rule.IsInherited -or $rule.AccessControlType -cne 'Allow' -or
    ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData)){throw 'transport DACL grants content writes'}
  }
 }
}finally{Remove-InstallationMemoryTransport $t}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("state", ("cancel", "missing-result", "61", "62", "63", "64", "65", "66"))
def test_real_dispatch_preserves_failure_and_cleans_transport(tmp_path, engine, state):
    result = run_functions(tmp_path, LIBRARY, ["Invoke-InstallationElevationCapture"], r'''
. $env:CA_CONTRACT_SOURCE
function Test-InstallationEvidencePrivileged {return $false}
function Get-InstallationEvidenceControlRoot {return (Join-Path $env:CA_CONTRACT_ROOT 'control')}
function Assert-InstallationEvidenceProtectedPath {}
function Write-InstallationEvidenceEvent {}
$Script:InstallationEvidenceRoot=$env:CA_CONTRACT_ROOT
function Start-Process {param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru)
 if($Verb -cne 'RunAs' -or $ArgumentList.Length -gt 16000){throw 'dispatch contract differs'}
 if($env:CA_TRANSPORT_STATE -ceq 'cancel'){throw [ComponentModel.Win32Exception]::new(1223,'fixture cancellation')}
 $exitCode=if($env:CA_TRANSPORT_STATE -ceq 'missing-result'){0}else{[int]$env:CA_TRANSPORT_STATE}
 return [pscustomobject]@{Id=4321;ExitCode=$exitCode}
}
$target=Join-Path (Split-Path -Parent (Split-Path -Parent $env:CA_CONTRACT_SOURCE)) 'INSTALL_THIS_PC.ps1'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$failure=$null
try{[void](Invoke-InstallationElevationCapture $target @('-File',$target) 'fixture-audit' $sid)}catch{$failure=$_}
if($null -eq $failure){throw 'failed/missing child result became success'}
if($env:CA_TRANSPORT_STATE -ceq 'cancel'){
 if($failure.Exception.NativeErrorCode -ne 1223){throw 'cancellation code changed'}
}elseif($env:CA_TRANSPORT_STATE -cne 'missing-result'){
 if((Get-InstallationPreparationExitCode $failure) -ne [int]$env:CA_TRANSPORT_STATE){throw 'preparation code changed'}
}
if(@(Get-ChildItem -LiteralPath $env:CA_CONTRACT_ROOT -File | Where-Object {$_.Name -cmatch '^[0-9a-f]{16}\.(ps1|dat)$'}).Count){throw 'private transport retained after failure'}
'PASS'
''', engine=engine, values={"CA_TRANSPORT_STATE": state})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("target", (0, 1))
@pytest.mark.parametrize("fault", ("utf8", "syntax"))
def test_matching_pin_still_rejects_invalid_utf8_ast_or_argument_shape(tmp_path, engine, target, fault):
    marker = tmp_path / "executed.txt"
    source = "[IO.File]::WriteAllText('%s','executed')" % str(marker).replace("'", "''")
    transport = prepare(tmp_path, engine, source, ["valid"])
    grant_fixture_owner_write(tmp_path, transport["Paths"], engine)
    path = Path(transport["Paths"][target])
    old_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    content = b"\xff" if fault == "utf8" else (b"{" if target == 0 else b"[null]")
    path.write_bytes(content)
    decoded = base64.b64decode(transport["Encoded"]).decode("utf-16-le")
    decoded = decoded.replace(old_digest, hashlib.sha256(content).hexdigest())
    encoded = base64.b64encode(decoded.encode("utf-16-le")).decode("ascii")
    result = child(engine, encoded)
    assert result.returncode == 1
    assert not marker.exists()

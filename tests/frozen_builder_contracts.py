"""Run the unmodified frozen-builder entrypoint with owned compiler/OS boundaries.

No application is built or frozen. Child processes are explicit PowerShell
command providers; the builder's gates, file copies, hashing, integrity records,
ZIP creation/extraction, receipt writes and call ordering execute unchanged.
The real authority, tag-parser and verifier implementations have separate tests.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "1" * 40
TREE = "2" * 40
TAG_OBJECT = "3" * 40


class FrozenBuilderHarness:
    def __init__(self, root, fault=""):
        self.root = root
        self.work = root / "work"
        self.output = root / "candidate"
        self.mirror = root / "mirror"
        self.mirror.mkdir()
        self.work.mkdir()
        self.fault = fault
        for relative in (
            "tools/build_frozen_release_candidate.ps1", "tools/bootstrap_integrity.ps1",
            "tools/direct_sync_relay_runner.py", "tools/direct_sync_relay_install_pack.py",
            "tools/direct_sync_relay_operator.py", "tools/register_container_audit_worker_pc.py",
            "tools/isolated_qualification_authority.py", "tools/install_logistics_runtime_profile.py",
            "tools/check_logistics_runtime_profile.py", "tools/provision_protected_admin_acl.ps1",
            "docs/PROTECTED_ADMIN_PROVISIONING.md", "docs/LOGISTICS_RUNTIME_PROFILE.md",
            "INSTALL_THIS_PC.ps1", "config/container_audit_settings.json",
        ):
            target = self.work / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        (self.work / "tools/pyinstaller_hooks").mkdir()
        for helper in ("resolve_release_python.ps1", "resolve_windows_powershell.ps1"):
            (self.work / "tools" / helper).write_text("# OS authority supplied by driver\n")
        (self.work / "tools/prepublish_release_gate.ps1").write_text(
            "Add-OwnedCall 'local_gate' $args\n", encoding="utf-8"
        )
        if fault == "existing_output":
            self.output.mkdir()
        if fault == "generated_input":
            (self.work / "build/factory_contract_identity").mkdir(parents=True)

    def run(self):
        engine = shutil.which("pwsh")
        if not engine:
            pytest.skip("PowerShell 7 is required for the frozen builder")
        driver = self.root / "driver.ps1"
        driver.write_text(DRIVER, encoding="utf-8")
        report = self.root / "calls.json"
        env = dict(os.environ, CA_BUILDER_ROOT=str(self.root), CA_BUILDER_FAULT=self.fault,
                   CA_BUILDER_REPORT=str(report))
        result = subprocess.run(
            [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver)],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=40,
        )
        return result, json.loads(report.read_text(encoding="utf-8"))


DRIVER = r'''
$ErrorActionPreference='Stop'
$global:caOwnedRoot=$env:CA_BUILDER_ROOT
$global:caOwnedFault=$env:CA_BUILDER_FAULT
$global:caOwnedCalls=[Collections.Generic.List[object]]::new()
$global:caOwnedError=''
$global:caOwnedCommit='1'*40
$global:caOwnedTree='2'*40
$global:caOwnedTag='3'*40
$global:caOwnedWork=Join-Path $caOwnedRoot 'work'
$global:caOwnedOutput=Join-Path $caOwnedRoot 'candidate'
$global:caOwnedMirror=Join-Path $caOwnedRoot 'mirror'
$global:caOwnedPython=Join-Path $caOwnedRoot 'sealed python.exe'
$global:caOwnedWindowsPowerShell=Join-Path $caOwnedRoot 'sealed powershell.exe'
function global:Add-OwnedCall($Kind, $Arguments) {
    $global:caOwnedCalls.Add([ordered]@{kind=$Kind;arguments=@($Arguments)})
}
function global:Write-OwnedJson($Path, $Value) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
    [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 12 -Compress))
}
function global:Register-OwnedExecutable($Path) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
    [IO.File]::WriteAllText($Path,'owned compiler output; not an executable')
    Set-Item -LiteralPath ('Function:global:'+$Path) -Value {
        param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Arguments)
        Invoke-OwnedChild $MyInvocation.MyCommand.Name $Arguments
    }
}
function global:Initialize-ReleasePythonAuthority {
    param($ExpectedPath,$ApprovedRoot,$ExpectedVersionMajor,$ExpectedVersionMinor,$ExpectedArchitectureBits)
    Add-OwnedCall 'python_authority' @($ExpectedPath,$ApprovedRoot,$ExpectedVersionMajor,$ExpectedVersionMinor,$ExpectedArchitectureBits)
    if ($caOwnedFault -ceq 'python_authority') {throw 'owned python authority refused'}
    return [pscustomobject]@{executable=$caOwnedPython;sha256=('4'*64);size=41;python_version='3.12.9';architecture_bits=64;machine='AMD64';implementation='CPython';file_product_version='3.12.9'}
}
function global:Initialize-WindowsPowerShellAuthority {
    param($ExpectedPath,$ExpectedSystemDirectory)
    Add-OwnedCall 'windows_authority' @($ExpectedPath,$ExpectedSystemDirectory)
    if ($caOwnedFault -ceq 'windows_authority') {throw 'owned Windows authority refused'}
    return [pscustomobject]@{executable=$caOwnedWindowsPowerShell;system_directory=$ExpectedSystemDirectory;file_type='File';is_reparse_point=$false;sha256=('5'*64);size=42;psedition='Desktop';powershell_version='5.1.1';version_major=5;version_minor=1;file_product_version='5.1.1'}
}
function global:Assert-ReleasePythonIdentity {
    param($ExpectedIdentity)
    Add-OwnedCall 'python_recheck' @($ExpectedIdentity.executable)
    if ($caOwnedFault -ceq 'python_drift') { $ExpectedIdentity=$ExpectedIdentity.PSObject.Copy(); $ExpectedIdentity.sha256='6'*64 }
    return $ExpectedIdentity
}
function global:Assert-WindowsPowerShellIdentity {
    param($ExpectedIdentity)
    Add-OwnedCall 'windows_recheck' @($ExpectedIdentity.executable)
    if ($caOwnedFault -ceq 'windows_drift' -and @($caOwnedCalls | Where-Object kind -ceq 'windows_recheck').Count -eq 2) {
        $ExpectedIdentity=$ExpectedIdentity.PSObject.Copy(); $ExpectedIdentity.sha256='6'*64
    }
    return $ExpectedIdentity
}
function global:git {
    param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Arguments)
    Add-OwnedCall 'git' $Arguments
    $global:LASTEXITCODE=0
    $mirror=$Arguments[0] -ceq '-C'
    $a=if ($mirror) {@($Arguments | Select-Object -Skip 2)} else {@($Arguments)}
    $command=$a -join ' '
    if ($command -ceq 'rev-parse --is-inside-work-tree') {return 'true'}
    if ($command -ceq 'rev-parse --show-toplevel') {return $caOwnedWork}
    if ($command -ceq 'rev-parse --is-bare-repository') {if ($caOwnedFault -ceq 'not_bare') {return 'false'};return 'true'}
    if ($a[0] -ceq 'status') {if ($caOwnedFault -ceq 'dirty') {return ' M app.py'};return ''}
    if ($command -ceq 'remote get-url origin') {if ($caOwnedFault -ceq 'origin') {return $caOwnedRoot};return $caOwnedMirror}
    if ($command -ceq 'symbolic-ref --quiet HEAD') {if ($caOwnedFault -ceq 'branch') {return 'refs/heads/topic'};return 'refs/heads/main'}
    if ($a[0] -ceq 'cat-file') {if ($caOwnedFault -ceq 'lightweight') {return 'commit'};return 'tag'}
    if ($a[0] -ceq 'show') {return '1700000000'}
    if ($a[0] -cne 'rev-parse') {throw "unexpected builder Git command: $command"}
    $ref=$a[-1]
    if ($ref -like '*^{tree}') {return $caOwnedTree}
    if ($ref -ceq 'refs/heads/main^{commit}' -and $mirror -and $caOwnedFault -ceq 'main') {return '7'*40}
    if ($ref -like 'refs/tags/*^{commit}') {if ($caOwnedFault -ceq 'peel') {return '7'*40};return $caOwnedCommit}
    if ($ref -like 'refs/tags/*') {if ($mirror -and $caOwnedFault -ceq 'tag_object') {return '7'*40};return $caOwnedTag}
    return $caOwnedCommit
}
function global:gh {throw 'the local builder must never use GitHub'}
function global:Invoke-OwnedChild($Executable, [object[]]$Arguments) {
    Add-OwnedCall 'child' (@($Executable)+@($Arguments))
    $global:LASTEXITCODE=0
    $a=@($Arguments | ForEach-Object {if ($_ -is [array]) {$_} else {$_}})
    function Arg($Name) {return [string]$a[[array]::IndexOf($a,$Name)+1]}
    if ($a -contains 'tools/read_release_qualification_tag.py') {
        if ($caOwnedFault -ceq 'parser_exit') {$global:LASTEXITCODE=2;return ''}
        $identity=@{tag_object_sha=$caOwnedTag;peeled_commit_sha=$caOwnedCommit;message='Release v1.0.0'}
        if ($caOwnedFault -ceq 'parser_identity') {$identity.message='Release wrong'}
        return ($identity | ConvertTo-Json -Compress)
    }
    if ($a -contains 'PyInstaller') {
        if ($caOwnedFault -ceq 'compiler') {$global:LASTEXITCODE=23;return}
        $dist=Arg '--distpath'
        if ($a -contains 'Container_Audit.spec') {
            $package=Join-Path $dist 'Container_Audit'
            Register-OwnedExecutable (Join-Path $package 'Container_Audit.exe')
            Copy-Item -LiteralPath (Join-Path $caOwnedWork 'build/release_tools') -Destination (Join-Path $package 'tools') -Recurse
            Copy-Item -LiteralPath (Join-Path $caOwnedWork 'build/release_config') -Destination (Join-Path $package 'config') -Recurse
            if ($caOwnedFault -ceq 'native_dependency') {
                $bad=Join-Path $package 'PIL/bad.pyd';[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($bad)) | Out-Null;[IO.File]::WriteAllText($bad,'native contamination')
            }
        } else { Register-OwnedExecutable (Join-Path $dist ((Arg '--name')+'.exe')) }
        return
    }
    if ($a -contains 'build-identity') {
        Write-OwnedJson (Arg '-OutputPath') @{mode=(Arg '-WorkflowMode');commit=(Arg '-ProbeSourceCommit')};return
    }
    if ($a -contains 'kmtech_factory_contracts.build_cli') {
        if ($a -contains 'prepare') {
            $bound=Get-Content -Raw -LiteralPath (Join-Path $caOwnedOutput 'FINAL_RELEASE_IDENTITY.json') | ConvertFrom-Json
            if ($bound.tag_object_sha -cne $caOwnedTag -or $bound.peeled_commit_sha -cne $caOwnedCommit) {throw 'build preparation preceded final identity binding'}
        }
        if ($a -contains 'manifest') {Write-OwnedJson (Join-Path (Arg '--stage-root') 'build-manifest.json') @{payload_inventory_sha256=('8'*64);payload_inventory=@(@{path='fixture'})}}
        return
    }
    if ($a -contains 'tools/check_update_archive.py') {
        Expand-Archive -LiteralPath (Arg '--zip-path') -DestinationPath (Arg '--destination')
        foreach ($exe in Get-ChildItem -LiteralPath (Arg '--destination') -Filter '*.exe' -Recurse) {
            # Register the child boundary without changing the just-extracted bytes.
            Set-Item -LiteralPath ('Function:global:'+$exe.FullName) -Value {
                param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Arguments)
                Invoke-OwnedChild $MyInvocation.MyCommand.Name $Arguments
            }
        }
        return
    }
    if ($a -contains 'tools/verify_frozen_release_artifact.py') {
        $status=if ($caOwnedFault -ceq 'verifier') {'FAIL'} else {'PASS_SELF_CONSISTENCY'}
        Write-OwnedJson (Arg '--report-path') @{status=$status;bootstrap_integrity=@{status='PASS'};governing_local_byte_parity=@{status='NOT_TESTED'};archive=@{exact_manifest_membership=$true}}
        return
    }
    if ($a -contains 'tools/check_release_config.py' -and $a -contains '-B') {
        if ($caOwnedFault -ceq 'post_smoke_write') {[IO.File]::WriteAllText((Join-Path $caOwnedOutput 'smoke/Container_Audit/changed.pyc'),'unexpected bytecode')}
        if ($caOwnedFault -ceq 'identity_file_drift') {[IO.File]::AppendAllText((Join-Path $caOwnedOutput 'FINAL_RELEASE_IDENTITY.json'),' ')}
        return
    }
    if ($a -contains '-c' -and $caOwnedFault -ceq 'pyinstaller_version') {$global:LASTEXITCODE=2;return}
    if ($a -contains '--help' -or $a -contains '--dry-run' -or $a -contains '-DryRun' -or
        $a -contains 'tools/check_release_version.py' -or $a -contains '-c' -or
        $a -contains 'pip' -or $a -contains 'tools/stage_pure_python_charset_normalizer.py' -or
        $a -contains 'tools/check_release_config.py') {return}
    throw ('unexpected owned child arguments: '+($a -join ' '))
}
Register-OwnedExecutable $caOwnedPython
Register-OwnedExecutable $caOwnedWindowsPowerShell
try {
    & (Join-Path $caOwnedWork 'tools/build_frozen_release_candidate.ps1') -Tag 'v1.0.0' -OutputRoot $caOwnedOutput -MirrorRoot $caOwnedMirror -PythonExecutable $caOwnedPython
} catch {$global:caOwnedError=$_.Exception.Message}
finally {Write-OwnedJson $env:CA_BUILDER_REPORT @{calls=@($caOwnedCalls);error=$caOwnedError}}
if ($caOwnedError) {[Console]::Error.WriteLine($caOwnedError);exit 1}
'''

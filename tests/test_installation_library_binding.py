"""Execute actual bootstrap-load clauses with owned libraries and byte pins."""
from pathlib import Path
import os
import shutil

import pytest

from tests.powershell_contracts import run_powershell


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("binding", ("pinned", "administrator"))
@pytest.mark.parametrize("valid", (True, False))
def test_bootstrap_library_load_preserves_verified_bytes_and_original_path(
    tmp_path: Path, engine: str, binding: str, valid: bool,
) -> None:
    # The tested bodies are taken from the real installer AST. No host token,
    # registry, credential or task API is called by either selected body.
    command = r'''
$ErrorActionPreference='Stop'
$source=Join-Path $env:CA_LIBRARY_SOURCE 'INSTALL_THIS_PC.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'installer parse failed'}
$statement=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -ceq '$pinnedLibrary'
},$true))
if($statement.Count -ne 1){throw 'bound library branch differs'}
$root=$env:CA_LIBRARY_FIXTURE
$library=Join-Path $root 'library.ps1'
$other=Join-Path $root 'other.ps1'
[IO.File]::WriteAllText($library,'function Test-OwnedLibraryLoaded { return 17 }')
[IO.File]::WriteAllText($other,'function Test-OwnedLibraryLoaded { return 19 }')
$BootstrapIntegrityFunctions=$library
$originalPath=$BootstrapIntegrityFunctions
if($env:CA_LIBRARY_BINDING -ceq 'pinned'){
    $parsePath=if($env:CA_LIBRARY_VALID -ceq '1'){$library}else{$other}
    $pinnedLibrary=[Management.Automation.Language.Parser]::ParseFile(
        $parsePath,[ref]$tokens,[ref]$errors).GetScriptBlock()
    $body=$statement[0].Clauses[0].Item2.Statements.Extent.Text -join "`n"
}else{
    $digest=(Get-FileHash -LiteralPath $library -Algorithm SHA256).Hash.ToLowerInvariant()
    if($env:CA_LIBRARY_VALID -cne '1'){$digest='0'*64}
    [IO.File]::WriteAllText((Join-Path $root 'portable-manifest.json'),
        (@{integrity_helper_sha256=$digest}|ConvertTo-Json -Compress))
    $body=$statement[0].Clauses[1].Item2.Statements.Extent.Text -join "`n"
}
$accepted=$false;$failure=''
$bodyPath=Join-Path $root 'bound-clause.ps1'
[IO.File]::WriteAllText($bodyPath,$body)
try{. $bodyPath;$accepted=$true}catch{$failure=$_.Exception.Message}
if($BootstrapIntegrityFunctions -cne $originalPath){throw 'original library path changed'}
if($env:CA_LIBRARY_VALID -ceq '1'){
    if(-not $accepted -or (Test-OwnedLibraryLoaded) -ne 17){throw 'verified library was not loaded'}
}else{
    $expected=if($env:CA_LIBRARY_BINDING -ceq 'pinned'){
        'Pinned bootstrap library identity differs.'
    }else{'Bootstrap integrity producer byte pin differs.'}
    if($accepted -or $failure -cne $expected -or
        (Get-Command Test-OwnedLibraryLoaded -ErrorAction SilentlyContinue)){
        throw 'invalid library binding was accepted'
    }
}
'BOUND_LIBRARY_PASS'
'''
    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required for executable library contracts")
    driver = tmp_path / "load-library-driver.ps1"
    driver.write_text(command, encoding="utf-8-sig")
    environment = dict(os.environ, CA_LIBRARY_SOURCE=str(ROOT),
                       CA_LIBRARY_FIXTURE=str(tmp_path), CA_LIBRARY_BINDING=binding,
                       CA_LIBRARY_VALID="1" if valid else "0")
    result = run_powershell(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver)],
        env=environment, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BOUND_LIBRARY_PASS" in result.stdout

"""Execute selected product PowerShell functions without running installer entrypoints."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


def run_functions(tmp_path, source, names, script, *, values=None, engine='powershell.exe'):
    powershell = shutil.which(engine)
    if not powershell:
        pytest.skip(f'{engine} is required for executable function contracts')
    driver = tmp_path/'contract.ps1'
    driver.write_text(r'''
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'product PowerShell parse failed' }
foreach ($name in $env:CA_CONTRACT_NAMES.Split(',')) {
    $functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if ($functions.Count -ne 1) { throw ('expected one actual product function: '+$name) }
    Invoke-Expression $functions[0].Extent.Text
}
''' + script,encoding='utf-8-sig')
    environment=dict(os.environ,CA_CONTRACT_SOURCE=str(Path(source).resolve()),
                     CA_CONTRACT_NAMES=','.join(names),CA_CONTRACT_ROOT=str(tmp_path))
    environment.update(values or {})
    return subprocess.run([powershell,'-NoLogo','-NoProfile','-NonInteractive','-File',str(driver)],
                          env=environment,capture_output=True,text=True,timeout=30)

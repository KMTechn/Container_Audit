"""Execute selected product PowerShell functions without running installer entrypoints."""
import os
import io
from pathlib import Path
import re
import shutil
import subprocess

import pytest


def run_powershell(arguments, *, check=False, capture_output=True, text=True, **kwargs):
    """Use a strict UTF-8 text protocol for owned PowerShell test invocations.

    -File scripts still run in their own script scope with named parameters.
    Binary capture keeps a decoding error on the calling thread, instead of
    subprocess's Windows reader thread losing a stream and returning None.
    """
    if capture_output is not True or text is not True:
        raise ValueError('PowerShell contract helper requires captured text')
    argv = list(arguments)
    mode = next(i for i, value in enumerate(argv) if value.lower() in ('-file', '-command'))
    prefix = '[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); $OutputEncoding = [Console]::OutputEncoding; '
    if argv[mode].lower() == '-command':
        if len(argv) != mode + 2:
            raise ValueError('PowerShell -Command requires one complete script')
        command = argv[mode + 1]
    else:
        def literal(value):
            return "'" + str(value).replace("'", "''") + "'"

        parameters = [value if re.fullmatch(r'-[A-Za-z][A-Za-z0-9]*', value) else literal(value)
                      for value in argv[mode + 2:]]
        command = '& ' + literal(argv[mode + 1]) + ' ' + ' '.join(parameters)
        command += '; if (-not $?) { if ($LASTEXITCODE) { exit $LASTEXITCODE }; exit 1 }; exit 0'
    completed = subprocess.run(
        [*argv[:mode], '-Command', prefix + command],
        capture_output=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), **kwargs,
    )
    def decode(data):
        with io.TextIOWrapper(io.BytesIO(data), encoding='utf-8', errors='strict') as stream:
            return stream.read()

    result = subprocess.CompletedProcess(
        arguments, completed.returncode,
        decode(completed.stdout), decode(completed.stderr),
    )
    if check:
        result.check_returncode()
    return result


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
    return run_powershell([powershell,'-NoLogo','-NoProfile','-NonInteractive','-File',str(driver)],
                          env=environment,capture_output=True,text=True,timeout=30)

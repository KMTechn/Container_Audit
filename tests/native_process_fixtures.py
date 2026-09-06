"""Build a tiny owned argument recorder, never an application release binary."""
import os
from pathlib import Path
import subprocess

import pytest


@pytest.fixture(scope='module')
def native_argument_recorder(tmp_path_factory):
    if os.name != 'nt':
        pytest.skip('native Windows executable fixture requires Windows')
    root = tmp_path_factory.mktemp('argument-recorder')
    executable = root / 'recorder.exe'
    script = root / 'compile.ps1'
    escaped = str(executable).replace("'", "''")
    script.write_text(r'''
$ErrorActionPreference = 'Stop'
$source = @'
using System;
using System.IO;
using System.Runtime.Serialization.Json;
public static class ArgumentRecorder {
    public static int Main(string[] args) {
        using (var stream = File.Create(Environment.GetEnvironmentVariable("CA_ARGUMENT_RECEIPT"))) {
            new DataContractJsonSerializer(typeof(string[])).WriteObject(stream, args);
        }
        return Int32.Parse(Environment.GetEnvironmentVariable("CA_ARGUMENT_EXIT_CODE") ?? "0");
    }
}
'@
Add-Type -TypeDefinition $source -ReferencedAssemblies System.Runtime.Serialization,System.Xml -OutputAssembly '__EXE__' -OutputType ConsoleApplication
'''.replace('__EXE__', escaped), encoding='utf-8-sig')
    powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-1600:]
    assert executable.is_file()
    return executable

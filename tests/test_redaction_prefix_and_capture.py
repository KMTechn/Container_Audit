"""Local regressions pending the shared four-vector contract publication."""
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

import pytest

import auto_update

ROOT = Path(__file__).resolve().parents[1]
CASES = ('exception-prefix', 'mapping-prefix', 'long-assignment', 'long-exception-assignment')


def _sample(case):
    fragment = secrets.token_hex(20)
    value = fragment * (5000 if case.startswith('long-') else 1)
    prefix = {'exception-prefix': 'RuntimeError: ', 'mapping-prefix': '{"x": "y"} ',
              'long-assignment': '', 'long-exception-assignment': 'RuntimeError: '}[case]
    return prefix + 'password=' + value + '\nSAFE-END', fragment


def _require_safe(raw, fragment, label):
    hits = raw.count(fragment.encode()) + raw.count(fragment.encode('utf-16le'))
    if hits or len(raw) > 65536 or b'SAFE-END' not in raw:
        pytest.fail(f'{label}: original-fragment-count={hits}, saved-bytes={len(raw)}', pytrace=False)


def _common_ps(tmp_path, engine, text):
    source, output = tmp_path / 'input.txt', tmp_path / 'safe.txt'
    source.write_text(text, encoding='utf-8')
    script = tmp_path / 'common.ps1'
    script.write_text('''param($Root,$InputFile,$OutputFile)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'tools/bootstrap_integrity.ps1')
$safe=Protect-InstallationText ([IO.File]::ReadAllText($InputFile)) -1 -CommonOnly -Environment @{}
[IO.File]::WriteAllText($OutputFile,$safe,[Text.UTF8Encoding]::new($false))
''', encoding='utf-8')
    child = subprocess.run([shutil.which(engine), '-NoProfile', '-NonInteractive', '-File',
                            str(script), str(ROOT), str(source), str(output)],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if child.returncode or not output.exists():
        pytest.fail('Common PowerShell count probe did not complete', pytrace=False)
    return output.read_bytes()


@pytest.mark.parametrize('case', CASES)
def test_common_python_reexamines_sensitive_assignments(case):
    text, fragment = _sample(case)
    _require_safe(auto_update.redact_for_sink(text, {}).encode(), fragment, case)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('case', CASES)
def test_common_powershell_reexamines_sensitive_assignments(tmp_path, engine, case):
    text, fragment = _sample(case)
    _require_safe(_common_ps(tmp_path, engine, text), fragment, case)


@pytest.mark.parametrize('engine', ('python', 'powershell.exe', 'pwsh.exe'))
def test_assignment_inside_diagnostic_json_keeps_valid_json(tmp_path, engine):
    fragment = secrets.token_hex(20)
    text = json.dumps({'failure': 'RuntimeError: password=' + fragment, 'safe': 'SAFE-END'})
    raw = (auto_update.redact_for_sink(text, {}).encode() if engine == 'python'
           else _common_ps(tmp_path, engine, text))
    _require_safe(raw, fragment, 'diagnostic JSON')
    try:
        payload = json.loads(raw)
    except ValueError:
        pytest.fail('Diagnostic assignment redaction broke JSON framing', pytrace=False)
    if payload['safe'] != 'SAFE-END':
        pytest.fail('Diagnostic assignment redaction lost safe metadata', pytrace=False)


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('case', CASES[2:])
def test_native_capture_redacts_long_assignment_before_bounding(tmp_path, engine, case):
    text, fragment = _sample(case)
    source = tmp_path / 'input.txt'
    source.write_text(text, encoding='utf-8')
    child_script = tmp_path / 'child.py'
    child_script.write_text('import pathlib,sys\ntext=pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")\nsys.stdout.write(text)\nsys.stderr.write(text)\n', encoding='utf-8')
    capture, counts = tmp_path / 'capture.ps1', tmp_path / 'counts.json'
    capture.write_text('''param($Root,$Python,$Child,$InputFile,$OutputFile)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'tools/bootstrap_integrity.ps1')
Initialize-InstallationChildCapture
$result=[KMTechInstallationChildCapture]::Run($Python,@('-B',$Child,$InputFile),(Split-Path $InputFile),$null)
$stdout=ConvertTo-SafeInstallationOutput $result.stdout
$stderr=ConvertTo-SafeInstallationOutput $result.stderr
$original=[IO.File]::ReadAllText($InputFile)
$fragment=[regex]::Match($original,'password=([a-f0-9]{40})').Groups[1].Value
$details=@()
foreach($stream in @($stdout,$stderr)){
 $raw=[Text.Encoding]::UTF8.GetString($stream.bytes)
 $details+=@{original_fragment_count=([regex]::Matches($raw,[regex]::Escape($fragment))).Count;saved_bytes=$stream.bytes.Length;safe_end=$raw.Contains('SAFE-END')}
}
[IO.File]::WriteAllText($OutputFile,(ConvertTo-Json -InputObject $details -Compress),[Text.UTF8Encoding]::new($false))
''', encoding='utf-8')
    child = subprocess.run([shutil.which(engine), '-NoProfile', '-NonInteractive', '-File', str(capture),
                            str(ROOT), sys.executable, str(child_script), str(source), str(counts)],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if child.returncode or not counts.exists():
        pytest.fail('Native capture count probe did not complete', pytrace=False)
    for result in json.loads(counts.read_bytes()):
        if result['original_fragment_count'] or result['saved_bytes'] > 65536 or not result['safe_end']:
            pytest.fail('Native capture ' + json.dumps(result, sort_keys=True), pytrace=False)

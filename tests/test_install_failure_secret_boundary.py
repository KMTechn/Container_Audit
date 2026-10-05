from pathlib import Path
from types import SimpleNamespace
import json
import os
import secrets
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[1]
SECRET_NAMES = (
    "CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN", "KM_LOGISTICS_INSTALL_BEARER_TOKEN",
)


def _check_and_scrub_artifacts(payloads, values, artifact=None):
    leaked = any(value.encode() in payload for value in values for payload in payloads)
    if artifact is not None and artifact.exists():
        raw = artifact.read_bytes()
        for value in values:
            raw = raw.replace(value.encode(), b"[REDACTED]")
        artifact.write_bytes(raw)
    if leaked:
        raise AssertionError("known secret bytes exposed in failure output or audit")


@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh.exe"])
def test_canonical_failure_console_and_audit_remove_known_secret_bytes(tmp_path, shell):
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip("PowerShell host unavailable")
    values = [secrets.token_hex(32) for _ in SECRET_NAMES]
    environment = os.environ.copy()
    environment.update(dict(zip(SECRET_NAMES, values)))
    script = tmp_path / "private-boundary.ps1"
    script.write_text(r"""param($Source,$Audit)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'canonical parse failed'}
foreach($name in @('ConvertTo-CanonicalSafeDiagnostic','Save')){
    $found=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
    if($found.Count -ne 1){throw 'diagnostic function missing'}
    Invoke-Expression $found[0].Extent.Text
}
$value=[Environment]::GetEnvironmentVariable('CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN','Process')
$other=[Environment]::GetEnvironmentVariable('KM_LOGISTICS_INSTALL_BEARER_TOKEN','Process')
Save $Audit @{status='FAILED';failure_code='PRODUCT_FAILED';child_output=$value;nested=@{stderr=$other}} $true
Write-Output (ConvertTo-CanonicalSafeDiagnostic ('PRODUCT_FAILED: '+$value+' '+$other))
""", encoding="utf-8")
    audit = tmp_path / "audit.json"
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-File", str(script),
         str(REPO / "INSTALL_CANONICAL_PORTABLE.ps1"), str(audit)],
        env=environment, capture_output=True, timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    payloads = [result.stdout, result.stderr, audit.read_bytes() if audit.exists() else b""]
    _check_and_scrub_artifacts(payloads, values, audit)
    if result.returncode:
        raise AssertionError("isolated diagnostic boundary fixture failed")
    document = json.loads(payloads[2])
    assert document["failure_code"] == "PRODUCT_FAILED"
    assert document["child_output"] == "[REDACTED]"
    assert document["nested"]["stderr"] == "[REDACTED]"


def test_relay_install_command_and_audit_remove_known_secret_bytes(tmp_path, monkeypatch):
    from tools import direct_sync_relay_install_pack as pack
    values = [secrets.token_hex(32) for _ in SECRET_NAMES]
    for name, value in zip(SECRET_NAMES, values):
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setattr(pack.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=1, stdout=values[0], stderr=values[1],
    ))
    result = pack._run_command(["isolated-owned-child"])
    audit = tmp_path / "audit.json"
    pack._write_json(audit, {"failure_code": "CHILD_FAILED", "command_result": result,
                             "nested": {"untrusted_child_output": values}})
    payload = audit.read_bytes()
    _check_and_scrub_artifacts([json.dumps(result).encode(), payload], values, audit)
    assert json.loads(payload)["failure_code"] == "CHILD_FAILED"
    assert result["returncode"] == 1
    assert result["stdout"] == "[REDACTED]"
    assert result["stderr"] == "[REDACTED]"

    escaped_values = [value + chr(34) + chr(92) + chr(0xAC00) for value in values]
    for name, value in zip(SECRET_NAMES, escaped_values):
        monkeypatch.setenv(name, value)
    encoded = json.dumps(escaped_values, ensure_ascii=True)
    redacted = pack._redact_install_diagnostic(encoded)
    assert json.loads(redacted) == ['[REDACTED]', '[REDACTED]']
    pack._write_json(audit, {'failure_code': 'CHILD_FAILED', escaped_values[0]: encoded})
    payload = audit.read_bytes()
    representations = escaped_values + [json.dumps(value, ensure_ascii=True)[1:-1] for value in escaped_values]
    _check_and_scrub_artifacts([audit], representations, [payload, redacted.encode()])
    assert json.loads(payload)['failure_code'] == 'CHILD_FAILED'


def test_profile_install_failure_does_not_echo_secret_exception(tmp_path, monkeypatch, capsys):
    from tools import install_logistics_runtime_profile as installer
    value = secrets.token_hex(32)
    monkeypatch.setenv("KM_LOGISTICS_INSTALL_BEARER_TOKEN", value)
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(tmp_path / "data"))
    reached = []
    def refuse(*args, **kwargs):
        reached.append(True)
        raise RuntimeError(value)
    monkeypatch.setattr(installer, "install_runtime_profile", refuse)
    code = installer.main([
        "--profile-path", str(tmp_path / "profile.json"), "--base-url", "https://invalid.example",
        "--authority-scope", "isolated", "--authority-epoch", "1", "--plane-epoch", "1",
        "--device-id", "isolated", "--source-host-id", "isolated", "--dry-run",
    ])
    output = capsys.readouterr()
    _check_and_scrub_artifacts([output.out.encode(), output.err.encode()], [value])
    assert reached == [True]
    assert code == 2
    assert "BLOCKED: RuntimeError" in output.err

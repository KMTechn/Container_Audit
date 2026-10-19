"""Shared contract #31 (main version) metadata vectors, using synthetic environments only."""
import hashlib
import json
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
VECTOR_FILE = ROOT / "tests/fixtures/installation_redaction_vectors.json"
PIN_FILE = ROOT / "docs/failure-redaction-contract.sha256.json"
# The published pair: the contract document and the vector file stay byte-identical to it.
CONTRACT_SHA256 = "c12e742fe3c5ba90c0771c69ddccbbe0e75b8b41c1f1672a9920c22f15fb78a8"
VECTORS_SHA256 = "9f19eeef81d08093d956e4ad6f9a781b9648ce74da7a2eccd090cc7f202f01d3"
METADATA_VECTORS = json.loads(VECTOR_FILE.read_bytes())["metadata_vectors"]


def test_contract_artifacts_are_byte_pinned_to_the_published_pair():
    manifest = json.loads(PIN_FILE.read_bytes())
    assert manifest["CONTRACT_SHA256"] == CONTRACT_SHA256
    assert manifest["VECTORS_SHA256"] == VECTORS_SHA256
    for key, relative in manifest["files"].items():
        data = (ROOT / relative).read_bytes()
        assert b"\r" not in data, "contract artifact must stay LF: " + key
        assert hashlib.sha256(data).hexdigest() == manifest[key], "contract artifact byte pin differs: " + key


def test_python_metadata_contract_vectors(tmp_path):
    import auto_update
    from tools.register_container_audit_worker_pc import _write_registration_json

    assert [vector["id"] for vector in METADATA_VECTORS], "metadata vectors missing"
    for index, vector in enumerate(METADATA_VECTORS):
        if vector["operation"] == "credential_write":
            target = tmp_path / str(index) / "credential.json"
            payload = json.loads(vector["text"])
            _write_registration_json(target, payload)
            if json.loads(target.read_text(encoding="utf-8")) != payload:
                pytest.fail("credential vector round trip failed: " + vector["id"])
            actual = "pass"
        else:
            try:
                auto_update.assert_machine_metadata_no_secrets(vector["text"], vector["environ"])
            except ValueError as error:
                if str(error) != "MACHINE_METADATA_SECRET_DETECTED":
                    pytest.fail("metadata diagnostic changed: " + vector["id"])
                actual = "reject"
            else:
                actual = "pass"
        if actual != vector["expected"]:
            pytest.fail("metadata vector failed: " + vector["id"])


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_metadata_contract_vectors(engine, tmp_path):
    path = tmp_path / "metadata-vectors.json"
    path.write_text(json.dumps(METADATA_VECTORS), encoding="utf-8")
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
                           ["Test-InstallationShortSecretValue", "Protect-InstallationText",
                            "Assert-InstallationMachineMetadataNoSecrets"], r'''
$vectors = Get-Content -LiteralPath $env:CA_VECTOR_PATH -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($vector in $vectors) {
    if ($vector.operation -eq 'credential_write') { continue }
    $environment = $null
    if ($null -ne $vector.environ) {
        $environment = @{}
        foreach ($property in $vector.environ.PSObject.Properties) {
            $environment[$property.Name] = [string]$property.Value
        }
    }
    $actual = 'pass'
    try { Assert-InstallationMachineMetadataNoSecrets -Json $vector.text -Environment $environment }
    catch {
        if ($_.Exception.Message -cne 'BOOTSTRAP_MACHINE_METADATA_SECRET_DETECTED') { throw 'metadata diagnostic changed' }
        $actual = 'reject'
    }
    if ($actual -ne $vector.expected) { throw ('metadata vector failed: ' + $vector.id) }
}
# Omission, null and an empty table are all an empty environment, never the process one.
$material = [guid]::NewGuid().ToString('N')
[Environment]::SetEnvironmentVariable('S412_BOOTSTRAP_TOKEN', $material, 'Process')
Assert-InstallationMachineMetadataNoSecrets -Json $material
Assert-InstallationMachineMetadataNoSecrets -Json $material -Environment $null
Assert-InstallationMachineMetadataNoSecrets -Json $material -Environment @{}
$rejected = $false
try { Assert-InstallationMachineMetadataNoSecrets -Json $material -Environment ([Environment]::GetEnvironmentVariables('Process')) }
catch { $rejected = $_.Exception.Message -ceq 'BOOTSTRAP_MACHINE_METADATA_SECRET_DETECTED' }
if (-not $rejected) { throw 'an explicitly passed process environment must still be checked' }
'PASS'
''', engine=engine, values={"CA_VECTOR_PATH": str(path)})
    assert result.returncode == 0, "PowerShell metadata vectors failed; raw values suppressed"
    assert result.stdout.strip() == "PASS"

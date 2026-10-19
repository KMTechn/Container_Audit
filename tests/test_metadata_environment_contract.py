"""Contract #31 (main version): metadata assertions use an explicit synthetic environment."""
import json
import uuid
from pathlib import Path

import pytest

from tests.powershell_contracts import run_functions

ROOT = Path(__file__).resolve().parents[1]
NAME = "S412_BOOTSTRAP_TOKEN"
ASTRAL = chr(0x1F600)
# value, Python code-point count rejects metadata, PowerShell UTF-16 length rejects metadata.
# The two languages count four characters differently outside the BMP: a pair of
# astral characters is two code points but four UTF-16 units. Each language keeps
# one boundary function for the assertion and the diagnostic redactor, and the
# PowerShell side is the stricter one. Change these rows together with the contract.
BOUNDARY_CASES = [
    ("bmp3", "s3!", False, False),
    ("bmp4", "s3!X", True, True),
    ("hangul4", "s4!" + chr(0xAC00), True, True),
    ("astral2", ASTRAL * 2, False, True),
    ("astral1-bmp2", "a" + ASTRAL + "b", False, True),
    ("astral3", ASTRAL * 3, False, True),
    ("astral4", ASTRAL * 4, True, True),
]


@pytest.mark.parametrize("explicit", [False, True])
def test_metadata_without_environment_does_not_consult_process(monkeypatch, explicit):
    import auto_update
    material = uuid.uuid4().hex
    monkeypatch.setenv(NAME, material)
    text = json.dumps({"fixture": material})
    if explicit:
        auto_update.assert_machine_metadata_no_secrets(text, None)
    else:
        auto_update.assert_machine_metadata_no_secrets(text)
    auto_update.assert_machine_metadata_no_secrets(text, {})
    with pytest.raises(ValueError, match="^MACHINE_METADATA_SECRET_DETECTED$"):
        auto_update.assert_machine_metadata_no_secrets(text, {NAME: material})


@pytest.mark.parametrize("material", ["s3!", "s3!X"])
def test_metadata_and_redaction_share_three_four_character_boundary(material):
    import auto_update
    environment = {NAME: material}
    text = json.dumps({"fixture": material})
    redacted = auto_update.redact_for_sink(text, environment)
    if len(material) == 3:
        auto_update.assert_machine_metadata_no_secrets(text, environment)
        assert material in redacted
        assert "short_value_skipped:" + NAME in redacted
    else:
        with pytest.raises(ValueError, match="^MACHINE_METADATA_SECRET_DETECTED$"):
            auto_update.assert_machine_metadata_no_secrets(text, environment)
        assert material not in redacted


@pytest.mark.parametrize("case", BOUNDARY_CASES, ids=lambda case: case[0])
def test_python_boundary_counts_code_points_for_metadata_and_redaction(case):
    import auto_update
    _, material, python_rejects, powershell_rejects = case
    # The table itself must follow the two counting rules it documents.
    assert python_rejects == (len(material) >= 4)
    assert powershell_rejects == (len(material.encode("utf-16-le")) // 2 >= 4)
    environment = {NAME: material}
    for ensure_ascii in (False, True):
        text = json.dumps({"fixture": material}, ensure_ascii=ensure_ascii)
        redacted = auto_update.redact_for_sink(text, environment)
        if python_rejects:
            with pytest.raises(ValueError, match="^MACHINE_METADATA_SECRET_DETECTED$"):
                auto_update.assert_machine_metadata_no_secrets(text, environment)
            assert "short_value_skipped:" + NAME not in redacted
        else:
            auto_update.assert_machine_metadata_no_secrets(text, environment)
            assert "short_value_skipped:" + NAME in redacted


@pytest.mark.parametrize("material", ["true", "null"])
def test_common_four_character_value_still_rejects_metadata(material):
    import auto_update
    with pytest.raises(ValueError, match="^MACHINE_METADATA_SECRET_DETECTED$") as caught:
        auto_update.assert_machine_metadata_no_secrets('{"present":' + material + '}', {NAME: material})
    assert str(caught.value) == "MACHINE_METADATA_SECRET_DETECTED"


@pytest.mark.parametrize("escaped", [False, True])
def test_metadata_rejects_long_synthetic_secret_including_json_escape(escaped):
    import auto_update
    material = "s4!" + chr(44032)
    text = json.dumps({"fixture": material}, ensure_ascii=escaped)
    with pytest.raises(ValueError, match="^MACHINE_METADATA_SECRET_DETECTED$"):
        auto_update.assert_machine_metadata_no_secrets(text, {NAME: material})


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_metadata_and_redaction_share_short_value_boundary(engine, tmp_path):
    cases = [{"id": row[0], "value": row[1], "reject": row[3]} for row in BOUNDARY_CASES]
    path = tmp_path / "boundary-cases.json"
    path.write_text(json.dumps(cases), encoding="utf-8")
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
                           ["Test-InstallationShortSecretValue", "Protect-InstallationText",
                            "Assert-InstallationMachineMetadataNoSecrets"], r'''
$cases = Get-Content -LiteralPath $env:CA_CASE_PATH -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($case in $cases) {
    $material = [string]$case.value
    $environment = @{ S412_BOOTSTRAP_TOKEN = $material }
    $text = @{ fixture = $material } | ConvertTo-Json -Compress
    $rejected = $false
    try { Assert-InstallationMachineMetadataNoSecrets -Json $text -Environment $environment }
    catch { $rejected = $_.Exception.Message -ceq 'BOOTSTRAP_MACHINE_METADATA_SECRET_DETECTED' }
    $redacted = Protect-InstallationText $text -1 -Environment $environment -CommonOnly
    $skipped = $redacted.Contains('short_value_skipped:S412_BOOTSTRAP_TOKEN')
    if ($rejected -ne [bool]$case.reject) { throw ('metadata boundary differs: ' + $case.id) }
    if ($skipped -eq [bool]$case.reject) { throw ('redaction boundary differs from metadata: ' + $case.id) }
    if ($rejected -and $redacted.Contains($material)) { throw ('long value left in redaction: ' + $case.id) }
    if (-not $rejected -and -not $redacted.Contains($material)) { throw ('short value was changed: ' + $case.id) }
}
'PASS'
''', engine=engine, values={"CA_CASE_PATH": str(path)})
    assert result.returncode == 0, "PowerShell short value boundary failed; raw values suppressed"
    assert result.stdout.strip() == "PASS"

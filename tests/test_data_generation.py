"""Executable Python/PS5.1/PS7 parity with literal, synthetic user data."""
import json
from pathlib import Path
import shutil

import pytest

from kmtech_shared import data_generation as generation
from tests.powershell_contracts import run_powershell

APP = "container_audit"
SID = "S-1-5-21-219"
BUILD = "a" * 40
OTHER_BUILD = "b" * 64
ROOT = Path(__file__).resolve().parents[1]


def record(path, version="v2.0.99", **options):
    return generation.record_generation(path, version, app_id=APP, subject_sid=SID, build_id=options.pop("build_id", BUILD), **options)


def probe(paths, target="v2.0.33", build_id=BUILD):
    return generation.probe_downgrade(paths, target, app_id=APP, subject_sid=SID, target_build_id=build_id)


def test_same_version_other_build_requires_explicit_signed_compatibility(tmp_path):
    marker = tmp_path / "generation.json"
    record(marker)
    assert probe([marker], "v2.0.99", BUILD)["status"] == "ALLOW"
    assert probe([marker], "v2.0.99", OTHER_BUILD)["status"] == "UNKNOWN"
    declared = tmp_path / "declared.json"
    record(declared, data_compatible_min_version="v2.0.99", compatibility_verified=True)
    assert probe([declared], "v2.0.99", OTHER_BUILD)["status"] == "ALLOW"
    implicit = tmp_path / "implicit.json"
    record(implicit, compatibility_verified=True)
    assert probe([implicit], "v2.0.99", OTHER_BUILD)["status"] == "UNKNOWN"
    assert probe([marker, declared], "v2.0.99", OTHER_BUILD)["status"] == "UNKNOWN"


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_same_version_build_binding(tmp_path, engine):
    plain, signed = tmp_path / "plain.json", tmp_path / "signed.json"
    record(plain)
    record(signed, data_compatible_min_version="v2.0.99", compatibility_verified=True)
    helper = str(ROOT / "kmtech_shared/powershell/data_generation.ps1").replace("'", "''")
    literal = lambda path: str(path).replace("'", "''")
    driver = tmp_path / "build-binding.ps1"
    driver.write_text(f"""
$ErrorActionPreference='Stop'
. '{helper}'
@(
 (Get-KmtechDataDowngradeDecision -MarkerPaths @('{literal(plain)}') -TargetVersion 'v2.0.99' -AppId '{APP}' -SubjectSid '{SID}' -TargetBuildId '{BUILD}')
 (Get-KmtechDataDowngradeDecision -MarkerPaths @('{literal(plain)}') -TargetVersion 'v2.0.99' -AppId '{APP}' -SubjectSid '{SID}' -TargetBuildId '{OTHER_BUILD}')
 (Get-KmtechDataDowngradeDecision -MarkerPaths @('{literal(signed)}') -TargetVersion 'v2.0.99' -AppId '{APP}' -SubjectSid '{SID}' -TargetBuildId '{OTHER_BUILD}')
) | ConvertTo-Json -Depth 5 -Compress
""", encoding="utf-8-sig")
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-File", str(driver)])
    assert result.returncode == 0, result.stderr
    assert [item["status"] for item in json.loads(result.stdout)] == ["ALLOW", "UNKNOWN", "ALLOW"]


def test_absent_generation_preserves_before_data_open_rollback(tmp_path):
    before = set(tmp_path.iterdir())
    result = probe([tmp_path / "machine.json", tmp_path / "user.json"])
    assert result["status"] == "ALLOW"
    assert set(tmp_path.iterdir()) == before


def test_direct_application_marker_denies_old_code_without_bootstrap_marker(tmp_path):
    user = tmp_path / "user.json"
    record(user)
    result = probe([tmp_path / "machine.json", user])
    assert result["status"] == "REFUSE"
    assert result["allowed"] is False
    assert "옛 판으로 되돌릴 수 없습니다" in result["message"]
    assert "백업" in result["message"]
    assert probe([user], "v2.0.99")["allowed"]
    assert probe([user], "v2.0.100")["allowed"]


def test_verified_compatibility_floor_is_honored_and_unsigned_floor_is_ignored(tmp_path):
    verified = tmp_path / "signed.json"
    unsigned = tmp_path / "unsigned.json"
    record(verified, data_compatible_min_version="v2.0.98", compatibility_verified=True)
    record(unsigned, data_compatible_min_version="v2.0.33")
    assert probe([verified], "v2.0.98")["status"] == "ALLOW"
    assert probe([verified], "v2.0.97")["status"] == "REFUSE"
    assert probe([unsigned])["status"] == "REFUSE"


def test_largest_generation_and_strictest_floor_at_same_generation(tmp_path):
    first, second = tmp_path / "machine.json", tmp_path / "user.json"
    record(first, "v2.0.98")
    record(second, "v2.0.99", data_compatible_min_version="v2.0.97", compatibility_verified=True)
    assert probe([first, second], "v2.0.97")["status"] == "ALLOW"
    record(first, "v2.0.99")
    assert probe([first, second], "v2.0.98")["status"] == "REFUSE"


@pytest.mark.parametrize("payload", [b"{", b"", b" " * 4097,
    b'{"schema":"kmtech-data-generation-v1","schema":"kmtech-data-generation-v1"}',
    json.dumps({"schema": generation.SCHEMA, "app_id": APP, "subject_sid": SID,
                "version": "commit-abc", "data_compatible_min_version": "v2.0.33"}).encode(),
    json.dumps({"schema": generation.SCHEMA, "app_id": APP, "subject_sid": "S-1-5-21-220",
                "version": "v2.0.99", "data_compatible_min_version": "v2.0.99"}).encode()])
def test_unreadable_or_invalid_marker_denies_even_with_valid_other_slot(tmp_path, payload):
    good, bad = tmp_path / "machine.json", tmp_path / "user.json"
    record(good)
    bad.write_bytes(payload)
    assert probe([good, bad], "v2.0.100")["status"] == "UNKNOWN"
    with pytest.raises((generation.DataGenerationError, ValueError)):
        record(bad)
    assert bad.read_bytes() == payload


def test_read_error_is_unknown_and_original_is_not_modified(tmp_path, monkeypatch):
    path = tmp_path / "marker.json"
    record(path)
    before = path.read_bytes()
    original = Path.open

    def denied(self, *args, **kwargs):
        if self == path:
            raise PermissionError("synthetic access refusal")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    assert probe([path])["status"] == "UNKNOWN"
    monkeypatch.setattr(Path, "open", original)
    assert path.read_bytes() == before


def test_file_ancestor_is_unknown_not_an_absent_marker(tmp_path):
    parent = tmp_path / "file-parent"
    parent.write_bytes(b"preserved")
    assert probe([parent / "marker.json"])["status"] == "UNKNOWN"
    assert parent.read_bytes() == b"preserved"


def test_atomic_failure_preserves_old_marker_and_high_water_never_decreases(tmp_path, monkeypatch):
    path = tmp_path / "marker.json"
    record(path, "v2.0.98")
    before = path.read_bytes()
    original = generation.os.replace

    def interrupted(*args):
        raise OSError("synthetic interrupted replacement")

    monkeypatch.setattr(generation.os, "replace", interrupted)
    with pytest.raises(OSError):
        record(path)
    assert path.read_bytes() == before
    assert not list(tmp_path.glob("*.tmp.*"))
    monkeypatch.setattr(generation.os, "replace", original)
    record(path)
    newest = path.read_bytes()
    record(path, "v2.0.33")
    assert path.read_bytes() == newest


def test_failed_readback_does_not_report_recording_success(tmp_path, monkeypatch):
    path = tmp_path / "marker.json"
    original = generation._read
    calls = []

    def missing_readback(*args):
        calls.append(args)
        return original(*args) if len(calls) == 1 else None

    monkeypatch.setattr(generation, "_read", missing_readback)
    with pytest.raises(generation.DataGenerationError, match="readback"):
        record(path)
    assert json.loads(path.read_bytes())["version"] == "v2.0.99"
    assert not list(tmp_path.glob("*.tmp.*"))


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_python_cross_reader_writer_parity(tmp_path, engine):
    assert shutil.which(engine), f"Required engine is unavailable: {engine}"
    py_marker, ps_marker = tmp_path / "python.json", tmp_path / "powershell.json"
    record(py_marker, data_compatible_min_version="v2.0.98", compatibility_verified=True)
    helper = str(ROOT / "kmtech_shared/powershell/data_generation.ps1").replace("'", "''")
    py_literal, ps_literal = (str(path).replace("'", "''") for path in (py_marker, ps_marker))
    driver = tmp_path / "parity.ps1"
    driver.write_text(f"""
$ErrorActionPreference='Stop'
. '{helper}'
$result = @()
$result += Get-KmtechDataDowngradeDecision @('{py_literal}') 'v2.0.98' '{APP}' '{SID}' '{BUILD}'
$result += Get-KmtechDataDowngradeDecision @('{py_literal}') 'v2.0.97' '{APP}' '{SID}' '{BUILD}'
$result += Get-KmtechDataDowngradeDecision @('{ps_literal}') 'v2.0.33' '{APP}' '{SID}' '{BUILD}'
[void](Write-KmtechDataGeneration '{ps_literal}' 'v2.0.98' '{APP}' '{SID}' -BuildId '{BUILD}')
[void](Write-KmtechDataGeneration '{ps_literal}' 'v2.0.99' '{APP}' '{SID}' 'v2.0.98' $true -BuildId '{BUILD}')
$result += Get-KmtechDataDowngradeDecision @('{ps_literal}') 'v2.0.98' '{APP}' '{SID}' '{BUILD}'
[void](Write-KmtechDataGeneration '{ps_literal}' 'v2.0.33' '{APP}' '{SID}' -BuildId '{BUILD}')
$result | ConvertTo-Json -Depth 5 -Compress
""", encoding="utf-8-sig")
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-File", str(driver)])
    assert result.returncode == 0, result.stderr
    decisions = json.loads(result.stdout)
    assert [item["status"] for item in decisions] == ["ALLOW", "REFUSE", "ALLOW", "ALLOW"]
    assert decisions[1]["message"] == generation.REFUSAL_MESSAGE
    assert probe([ps_marker], "v2.0.98")["status"] == "ALLOW"
    assert json.loads(ps_marker.read_bytes())["version"] == "v2.0.99"


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_invalid_and_two_slot_decisions(tmp_path, engine):
    assert shutil.which(engine)
    older, newer, corrupt = (tmp_path / name for name in ("older.json", "newer.json", "corrupt.json"))
    record(older, "v2.0.98")
    record(newer)
    corrupt.write_bytes(b"{")
    helper = str(ROOT / "kmtech_shared/powershell/data_generation.ps1").replace("'", "''")
    literal = lambda path: str(path).replace("'", "''")
    driver = tmp_path / "invalid.ps1"
    driver.write_text(f"""
$ErrorActionPreference='Stop'
. '{helper}'
@(
  (Get-KmtechDataDowngradeDecision @('{literal(older)}','{literal(newer)}') 'v2.0.98' '{APP}' '{SID}' '{BUILD}')
  (Get-KmtechDataDowngradeDecision @('{literal(newer)}','{literal(corrupt)}') 'v2.0.100' '{APP}' '{SID}' '{BUILD}')
  (Get-KmtechDataDowngradeDecision @('{literal(newer)}') 'commit-abc' '{APP}' '{SID}' '{BUILD}')
) | ConvertTo-Json -Depth 5 -Compress
""", encoding="utf-8-sig")
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-File", str(driver)])
    assert result.returncode == 0, result.stderr
    assert [item["status"] for item in json.loads(result.stdout)] == ["REFUSE", "UNKNOWN", "UNKNOWN"]


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_reparse_and_locked_marker_are_refused_without_changes(tmp_path, engine):
    target, link, marker = tmp_path / "target", tmp_path / "link", tmp_path / "locked.json"
    target.mkdir()
    record(marker)
    before = marker.read_bytes()
    helper = str(ROOT / "kmtech_shared/powershell/data_generation.ps1").replace("'", "''")
    literal = lambda path: str(path).replace("'", "''")
    driver = tmp_path / "literal.ps1"
    driver.write_text(f"""
$ErrorActionPreference='Stop'
. '{helper}'
[void](New-Item -ItemType Junction -Path '{literal(link)}' -Target '{literal(target)}')
$result = @()
$result += Get-KmtechDataDowngradeDecision @('{literal(link / 'marker.json')}') 'v2.0.33' '{APP}' '{SID}' '{BUILD}'
$handle=[IO.File]::Open('{literal(marker)}',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
try {{ $result += Get-KmtechDataDowngradeDecision @('{literal(marker)}') 'v2.0.100' '{APP}' '{SID}' '{BUILD}' }} finally {{ $handle.Dispose() }}
$result | ConvertTo-Json -Depth 5 -Compress
""", encoding="utf-8-sig")
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-File", str(driver)])
    assert result.returncode == 0, result.stderr
    assert [item["status"] for item in json.loads(result.stdout)] == ["UNKNOWN", "UNKNOWN"]
    assert probe([link / "marker.json"])["status"] == "UNKNOWN"
    with pytest.raises(generation.DataGenerationError):
        record(link / "marker.json")
    assert not list(target.iterdir())
    assert marker.read_bytes() == before


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_failed_readback_is_not_success(tmp_path, engine):
    marker = tmp_path / "marker.json"
    helper = str(ROOT / "kmtech_shared/powershell/data_generation.ps1").replace("'", "''")
    literal = str(marker).replace("'", "''")
    driver = tmp_path / "readback.ps1"
    driver.write_text(f"""
$ErrorActionPreference='Stop'
. '{helper}'
$script:originalRead=(Get-Item Function:Read-KmtechDataGeneration).ScriptBlock
$script:readCalls=0
function Read-KmtechDataGeneration([string]$Path,[string]$AppId,[string]$SubjectSid) {{
    $script:readCalls++
    if ($script:readCalls -gt 1) {{ return $null }}
    return (& $script:originalRead $Path $AppId $SubjectSid)
}}
$rejected=$false
try {{ [void](Write-KmtechDataGeneration '{literal}' 'v2.0.99' '{APP}' '{SID}' -BuildId '{BUILD}') }}
catch {{ $rejected=$_.Exception.Message -ceq 'Data generation durable readback differs.' }}
@{{rejected=$rejected}} | ConvertTo-Json -Compress
""", encoding="utf-8-sig")
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-File", str(driver)])
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["rejected"] is True
    assert json.loads(marker.read_bytes())["version"] == "v2.0.99"


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_file_ancestor_is_unknown_not_absent(tmp_path, engine):
    parent = tmp_path / "file-parent"
    parent.write_bytes(b"preserved")
    helper = str(ROOT / "kmtech_shared/powershell/data_generation.ps1").replace("'", "''")
    literal = str(parent / "marker.json").replace("'", "''")
    driver = tmp_path / "ancestor.ps1"
    driver.write_text(f"""
$ErrorActionPreference='Stop'
. '{helper}'
Get-KmtechDataDowngradeDecision @('{literal}') 'v2.0.33' '{APP}' '{SID}' '{BUILD}' | ConvertTo-Json -Compress
""", encoding="utf-8-sig")
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-File", str(driver)])
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "UNKNOWN"
    assert parent.read_bytes() == b"preserved"
def test_equal_version_new_build_retains_stricter_compatibility(tmp_path):
    identity = {"app_id": APP, "subject_sid": SID}
    marker = tmp_path / "new-build.json"
    generation.record_generation(marker, "v2.0.99", build_id="a" * 40,
        data_compatible_min_version="v2.0.33", compatibility_verified=True, **identity)
    assert generation.probe_downgrade([marker], "v2.0.99", target_build_id="b" * 40, **identity)["allowed"]
    updated = generation.record_generation(marker, "v2.0.99", build_id="b" * 40, **identity)
    assert updated["build_id"] == "b" * 40
    assert updated["data_compatible_min_version"] == "v2.0.99" and updated["compatibility_verified"] is False
    assert generation.probe_downgrade([marker], "v2.0.33", target_build_id="c" * 40, **identity)["status"] == "REFUSE"
    before = marker.read_bytes()
    generation.record_generation(marker, "v2.0.99", build_id="b" * 40,
        data_compatible_min_version="v2.0.33", compatibility_verified=True, **identity)
    assert marker.read_bytes() == before
    signed = tmp_path / "two-signed-builds.json"
    generation.record_generation(signed, "v2.0.99", build_id="a" * 40,
        data_compatible_min_version="v2.0.50", compatibility_verified=True, **identity)
    updated = generation.record_generation(signed, "v2.0.99", build_id="b" * 40,
        data_compatible_min_version="v2.0.33", compatibility_verified=True, **identity)
    assert updated["build_id"] == "b" * 40 and updated["data_compatible_min_version"] == "v2.0.50"
    assert updated["compatibility_verified"] is True


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_powershell_equal_version_build_does_not_inherit_floor(tmp_path, engine):
    helper = str(ROOT / "kmtech_shared/powershell/data_generation.ps1").replace("'", "''")
    marker = tmp_path / "new-build.json"
    second = tmp_path / "two-signed-builds.json"
    literal = lambda path: str(path).replace("'", "''")
    script = tmp_path / "same-version.ps1"
    script.write_text(f"""
$ErrorActionPreference='Stop'
. '{helper}'
[void](Write-KmtechDataGeneration '{literal(marker)}' 'v2.0.99' '{APP}' '{SID}' -BuildId ('a'*40) -DataCompatibleMinVersion 'v2.0.33' -CompatibilityVerified $true)
$updated=Write-KmtechDataGeneration '{literal(marker)}' 'v2.0.99' '{APP}' '{SID}' -BuildId ('b'*40)
$denied=Get-KmtechDataDowngradeDecision @('{literal(marker)}') 'v2.0.33' '{APP}' '{SID}' ('c'*40)
$before=[IO.File]::ReadAllText('{literal(marker)}')
[void](Write-KmtechDataGeneration '{literal(marker)}' 'v2.0.99' '{APP}' '{SID}' -BuildId ('b'*40) -DataCompatibleMinVersion 'v2.0.33' -CompatibilityVerified $true)
[void](Write-KmtechDataGeneration '{literal(second)}' 'v2.0.99' '{APP}' '{SID}' -BuildId ('a'*40) -DataCompatibleMinVersion 'v2.0.50' -CompatibilityVerified $true)
$strict=Write-KmtechDataGeneration '{literal(second)}' 'v2.0.99' '{APP}' '{SID}' -BuildId ('b'*40) -DataCompatibleMinVersion 'v2.0.33' -CompatibilityVerified $true
@{{updated=$updated;denied=$denied.status;same_preserved=($before -ceq [IO.File]::ReadAllText('{literal(marker)}'));strict=$strict}} | ConvertTo-Json -Depth 5 -Compress
""", encoding="utf-8-sig")
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-File", str(script)])
    assert result.returncode == 0, result.stderr
    detail = json.loads(result.stdout)
    assert detail["updated"]["build_id"] == "b" * 40
    assert detail["updated"]["data_compatible_min_version"] == "v2.0.99" and detail["updated"]["compatibility_verified"] is False
    assert detail["denied"] == "REFUSE" and detail["same_preserved"] is True
    assert detail["strict"]["data_compatible_min_version"] == "v2.0.50" and detail["strict"]["compatibility_verified"] is True

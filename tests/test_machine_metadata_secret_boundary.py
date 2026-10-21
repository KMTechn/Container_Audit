"""Machine integrity stays lossless; known secret content never reaches disk."""
import json
from pathlib import Path
import uuid

import pytest
from tests.powershell_contracts import run_functions
from tests.test_zero_touch_installer import _portable_release_fixture

ROOT = Path(__file__).resolve().parents[1]


def test_python_machine_serializer_preserves_large_original_json_and_rejects_secrets(monkeypatch):
    import auto_update
    payload = {'schema': 'machine-fixture', 'profile': {'large_value': 'a' * 90000},
               'transaction_id': uuid.uuid4().hex}
    monkeypatch.setattr(auto_update.os, 'environ', {})
    expected = json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2)
    assert auto_update.serialize_machine_metadata(payload) == expected
    synthetic = 'synthetic-only-machine-secret-' + uuid.uuid4().hex
    with pytest.raises(ValueError, match='^MACHINE_METADATA_SECRET_DETECTED$'):
        auto_update.assert_machine_metadata_no_secrets(json.dumps({'value': synthetic}),
                                                      {'CUSTOM_MACHINE_SECRET': synthetic})


@pytest.mark.parametrize('writer', ('control','onboarding','create_new'))
def test_python_machine_writers_leave_no_secret_temp(tmp_path, monkeypatch, writer):
    import auto_update
    import current_user_onboarding as onboarding
    synthetic = 'synthetic-only-machine-secret-' + uuid.uuid4().hex
    monkeypatch.setenv('CUSTOM_MACHINE_SECRET', synthetic)
    selected = {'control': auto_update.write_json_durable,
                'onboarding': onboarding._write_json_atomic,
                'create_new': onboarding._write_json_atomic_create_new}[writer]
    # Exercise the writer's implementation; file I/O and secret assertion are
    # real, while its normal admission is covered by module consumer tests.
    implementation = getattr(selected, '__wrapped__', selected)
    path = tmp_path/'machine.json'
    with pytest.raises(ValueError, match='^MACHINE_METADATA_SECRET_DETECTED$'):
        implementation(path, {'value': synthetic})
    assert not path.exists()
    assert not list(tmp_path.glob('*tmp'))


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_large_machine_integrity_roundtrip_and_one_byte_mutation(tmp_path, engine):
    packet = _portable_release_fixture(tmp_path, directory='packet')
    for i in range(600):
        (packet/f'owned-{i:04d}-long-identity-name.txt').write_bytes(b'exact owned bytes')
    manifest_path=packet/'portable-manifest.json'
    manifest=json.loads(manifest_path.read_text())
    files=[path for path in packet.rglob('*') if path.is_file() and path != manifest_path]
    manifest['file_count_before_manifest']=len(files)
    manifest['byte_count_before_manifest']=sum(path.stat().st_size for path in files)
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    result = run_functions(tmp_path, ROOT/'tools/bootstrap_integrity.ps1', ['Get-StrictFullPath'], r'''
. $env:CA_CONTRACT_SOURCE
$root=Join-Path $env:CA_CONTRACT_ROOT 'packet'
[void](Write-BootstrapIntegrityRecord -Root $root -CodeRootIdentity $root)
$path=Join-Path $root 'bootstrap-integrity.json'
if((Get-Item $path).Length -le 65536){throw 'large machine fixture was too small'}
$bytes=[IO.File]::ReadAllBytes($path)
if($bytes -contains 13 -or [Text.Encoding]::UTF8.GetString($bytes).Contains('[TRUNCATED:')){throw 'machine JSON bytes changed'}
[void](Assert-BootstrapIntegrityRecord $root)
[IO.File]::WriteAllText((Join-Path $root 'owned-0000-long-identity-name.txt'),'Exact owned bytes',[Text.UTF8Encoding]::new($false))
$rejected=$false
try{[void](Assert-BootstrapIntegrityRecord $root)}catch{$rejected=$true}
if(-not $rejected){throw 'one-byte mutation was admitted'}
'PASS_LOSSLESS_MACHINE_IDENTITY'
''', engine=engine)
    assert result.returncode == 0, 'lossless integrity native contract failed; diagnostics retained privately'
    assert result.stdout.strip() == 'PASS_LOSSLESS_MACHINE_IDENTITY'


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('name', ('CUSTOM_MACHINE_SECRET', 'CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN',
                                 'CONTAINER_AUDIT_WRITER_DELEGATION_SESSION_ID'))
def test_machine_secret_is_rejected_before_temporary_write(tmp_path, engine, name):
    synthetic = 'machine-secret-' + uuid.uuid4().hex
    result = run_functions(tmp_path, ROOT/'tools/bootstrap_integrity.ps1', ['Get-StrictFullPath'], r'''
. $env:CA_CONTRACT_SOURCE
$name=$env:CA_MACHINE_SECRET_NAME
$path=Join-Path $env:CA_CONTRACT_ROOT 'machine.json'
$value=[Environment]::GetEnvironmentVariable($name,'Process')
$rejected=$false
try{Write-Utf8Json $path @{schema='machine-fixture';value=$value}}catch{
    $rejected=$_.Exception.Message -ceq 'BOOTSTRAP_MACHINE_METADATA_SECRET_DETECTED'
}
if(-not $rejected -or (Test-Path $path) -or @(Get-ChildItem $env:CA_CONTRACT_ROOT -Filter 'machine.json*').Count){throw 'machine secret reached a file'}
'PASS_SECRET_REFUSED_NO_FILE'
''', engine=engine, values={name: synthetic, 'CA_MACHINE_SECRET_NAME': name})
    assert result.returncode == 0, 'machine secret rejection failed; raw values suppressed'
    assert result.stdout.strip() == 'PASS_SECRET_REFUSED_NO_FILE'
    raw = synthetic.encode()
    assert raw not in result.stdout.encode() and raw not in result.stderr.encode()
    assert all(raw not in path.read_bytes() for path in tmp_path.rglob('*') if path.is_file())


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
def test_audit_budget_keeps_valid_json_tuple_and_masks_diagnostics(tmp_path, engine):
    synthetic = 'audit-secret-' + uuid.uuid4().hex
    identity = uuid.uuid4().hex
    result = run_functions(tmp_path, ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',
        ['ConvertTo-CanonicalAuditJson','Save'], r'''$script:InstallationEvidenceRoot = $env:CA_CONTRACT_ROOT

$id=$env:CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID
$path=Join-Path $env:CA_CONTRACT_ROOT 'audit.json'
$body=('head-'+$env:CUSTOM_AUDIT_SECRET+' '+('가나다'*40000)+' tail '+$env:CUSTOM_AUDIT_SECRET)
Save $path @{schema='audit-fixture';code_replacement=@{transaction_id=$id};failure=@{message=$body};
    nested=@{delegation_token=$id};source_root=$env:CA_CONTRACT_ROOT}
$copy=Get-Content $path -Raw -Encoding UTF8|ConvertFrom-Json
if($copy.code_replacement.transaction_id -cne $id -or $copy.nested.delegation_token -cne '[REDACTED:field]'){throw 'identifier/secret field policy differs'}
if((Get-Item $path).Length -gt 65536 -or -not $copy.failure.message.Contains('[TRUNCATED:')){throw 'audit envelope budget differs'}
'PASS_VALID_BOUNDED_AUDIT'
''', engine=engine, values={'CUSTOM_AUDIT_SECRET': synthetic,
            'CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID': identity})
    assert result.returncode == 0, 'bounded audit native contract failed; raw diagnostics suppressed'
    assert result.stdout.strip() == 'PASS_VALID_BOUNDED_AUDIT'
    assert synthetic.encode() not in (tmp_path/'audit.json').read_bytes()
    assert json.loads((tmp_path/'audit.json').read_bytes())['code_replacement']['transaction_id'] == identity


def test_public_audit_save_masks_sensitive_bytes_and_keeps_valid_json(tmp_path):
    """Public Save must retain valid JSON without synthetic sensitive bytes."""
    import os

    synthetic = 'audit-secret-' + uuid.uuid4().hex
    identity = uuid.uuid4().hex
    result = run_functions(
        tmp_path,
        ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
        ['ConvertTo-CanonicalAuditJson', 'Save'],
        r"""
$id=$env:CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID
$path=Join-Path $env:CA_CONTRACT_ROOT 'audit.json'
$body=('head-'+$env:CUSTOM_AUDIT_SECRET+' '+('가나다'*40000)+' tail '+$env:CUSTOM_AUDIT_SECRET)
Save $path @{schema='audit-fixture';code_replacement=@{transaction_id=$id};failure=@{message=$body};}
'OK'
""",
        values={'CUSTOM_AUDIT_SECRET': synthetic, 'CONTAINER_AUDIT_WRITER_DELEGATION_TRANSACTION_ID': identity},
    )
    audit = tmp_path / 'audit.json'
    raw = audit.read_bytes() if audit.exists() else b""
    sensitive = synthetic.encode()
    counts = {
        "audit_occurrences": raw.count(sensitive),
        "stdout_occurrences": result.stdout.encode().count(sensitive),
        "stderr_occurrences": result.stderr.encode().count(sensitive),
    }
    valid_json = False
    try:
        json.loads(raw)
        valid_json = True
    except (ValueError, UnicodeDecodeError):
        pass
    if counts["audit_occurrences"]:
        audit.write_bytes(raw.replace(sensitive, b"[REMOVED]"))
    destination = Path(os.environ.get("KMTECH_TEST_CA_EVIDENCE_ROOT", str(tmp_path)))
    (destination / "p1-01-public-save-boundary.json").write_text(
        json.dumps({"returncode": result.returncode, "valid_json": valid_json,
                    **counts, "payloads_recorded": False}), encoding="utf-8"
    )
    if result.returncode:
        raise AssertionError("public Save fixture did not complete")
    if not valid_json:
        raise AssertionError("public Save did not preserve valid JSON")
    if any(counts.values()):
        raise AssertionError("public Save exposed synthetic sensitive bytes")

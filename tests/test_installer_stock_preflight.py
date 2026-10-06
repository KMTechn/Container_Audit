"""Stock preflight uses the admitted inventory; installed G still needs integrity."""
import hashlib
import json
from pathlib import Path

import pytest


def _aggregate(root):
    rows = [(p.relative_to(root).as_posix(), p) for p in root.rglob('*') if p.is_file()
            and p.relative_to(root).as_posix().casefold() != 'bootstrap-integrity.json']
    rows.sort(key=lambda row: row[0].encode('utf-16-be'))
    return hashlib.sha256(''.join(
        f'{hashlib.sha256(p.read_bytes()).hexdigest()} {p.stat().st_size} {name}\n'
        for name, p in rows).encode()).hexdigest()


@pytest.fixture
def stock(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding
    from tools import register_container_audit_worker_pc as registration
    root = tmp_path/'stock'
    app = root/'app'
    app.mkdir(parents=True)
    (app/'Container_Audit.py').write_bytes(b'CURRENT_VERSION = "v2.0.99"\n')
    (app/'__init__.py').write_bytes(b'')
    (root/'portable-manifest.json').write_text(json.dumps({
        'schema':'container-audit-portable-tree-v1','version':'v2.0.99',
        'source_commit':'a'*40,'source_tree':'b'*40}), encoding='utf-8')
    monkeypatch.setattr(registration, '_current_user_sid', lambda: 'S-1-5-21-416')
    values = {'CONTAINER_AUDIT_DATA_ROOT':str(tmp_path/'data'),
              'CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH':str(tmp_path/'data/profile.json'),
              'PROGRAMDATA':str(tmp_path/'program'), 'TEMP':str(tmp_path/'temp')}
    return root, app, values, onboarding


@pytest.mark.parametrize('marker', ('absent','newer','other-build'))
def test_stock_preflight_without_installation_record_keeps_generation_guards(stock, marker):
    from kmtech_shared import data_generation as generation
    root, app, values, onboarding = stock
    data = Path(values['CONTAINER_AUDIT_DATA_ROOT'])
    if marker != 'absent':
        data.mkdir()
        generation.record_generation(data/'data-generation.json', app_id='container_audit',
            subject_sid='S-1-5-21-416', version='v99.0.0' if marker=='newer' else 'v2.0.99',
            build_id='c'*40, data_compatible_min_version='v99.0.0' if marker=='newer' else 'v2.0.99',
            compatibility_verified=False)
    before = {p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
    if marker == 'absent':
        assert len(onboarding.preflight_current_user_onboarding(app, environ=values,
            installer_source_inventory_sha256=_aggregate(root))) == 64
        assert not data.exists()
    else:
        with pytest.raises(onboarding.CurrentUserOnboardingError):
            onboarding.preflight_current_user_onboarding(app, environ=values,
                installer_source_inventory_sha256=_aggregate(root))
    assert not (root/'bootstrap-integrity.json').exists()
    assert (app/'__init__.py').stat().st_size == 0
    assert before == {p:p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('mutation', ('wrong-pin','one-byte','extra-file','version','build'))
def test_source_inventory_and_release_identity_fail_closed(stock, mutation):
    root, app, values, onboarding = stock
    pin = _aggregate(root)
    if mutation == 'wrong-pin': pin = '0'*64
    elif mutation == 'one-byte': (app/'Container_Audit.py').write_bytes((app/'Container_Audit.py').read_bytes()+b' ')
    elif mutation == 'extra-file': (root/'extra.py').write_bytes(b'# unapproved\n')
    else:
        manifest = json.loads((root/'portable-manifest.json').read_bytes())
        manifest['version' if mutation=='version' else 'source_commit'] = 'v2.0.98' if mutation=='version' else 'invalid'
        (root/'portable-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        pin = _aggregate(root)
    with pytest.raises(onboarding.CurrentUserOnboardingError):
        onboarding.preflight_current_user_onboarding(app, environ=values,
            installer_source_inventory_sha256=pin)
    assert not Path(values['CONTAINER_AUDIT_DATA_ROOT']).exists()


def test_installed_identity_still_requires_record_after_source_probe(stock, monkeypatch):
    import data_generation_guard as guard
    root, app, values, onboarding = stock
    monkeypatch.setattr(guard, '__file__', str(app/'data_generation_guard.py'))
    onboarding.preflight_current_user_onboarding(app, environ=values,
        installer_source_inventory_sha256=_aggregate(root))
    assert guard._READONLY_INSTALLER_SOURCE.get() is None
    with pytest.raises(ValueError, match='release code integrity is not proven'):
        guard._runtime_release()
    (root/'bootstrap-integrity.json').write_bytes(b'{}')
    with pytest.raises(ValueError): guard._runtime_release()


def test_source_pin_cannot_enter_mutating_onboarding(stock, monkeypatch):
    _, app, _, onboarding = stock
    monkeypatch.setattr(onboarding, 'onboard_current_user', lambda *a, **kw: pytest.fail('mutating onboarding entered'))
    with pytest.raises(SystemExit) as error:
        onboarding.onboarding_main(['--app-root', str(app), '--installer-source-inventory-sha256', 'a'*64])
    assert error.value.code == 2


def test_source_pin_cannot_authorize_restore(stock):
    root, app, values, onboarding = stock
    with pytest.raises(onboarding.CurrentUserOnboardingError):
        onboarding.preflight_current_user_onboarding(app, environ=values,
            target_release_root=str(root), installer_source_inventory_sha256=_aggregate(root))


def test_source_snapshot_is_rechecked_before_publishing_binding(stock):
    import data_generation_guard as guard
    root, app, _, _ = stock
    with pytest.raises(ValueError, match='inventory binding differs'):
        with guard._readonly_installer_source(app, _aggregate(root)):
            (root/'late.txt').write_bytes(b'unapproved')
    assert guard._READONLY_INSTALLER_SOURCE.get() is None


@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
@pytest.mark.parametrize('prepared_paths', (True, False))
def test_canonical_early_admission_failure_has_fixed_status_and_audit(tmp_path, engine, prepared_paths):
    from tests.powershell_contracts import run_functions
    source = Path(__file__).resolve().parents[1]/'INSTALL_CANONICAL_PORTABLE.ps1'
    result = run_functions(tmp_path, source, ['Full','Get-CanonicalFailureDetails','Write-CanonicalPreparationAdmissionFailure'], r'''
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$null,[ref]$null)
$boundary=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[-1]
$early=@($boundary.CatchClauses[0].Body.Statements|Where-Object {$_.Extent.Text.StartsWith('if (-not $enteredPlacementTry')})
if($early.Count -ne 1){throw 'actual early catch missing'}
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'canonical-portable-failure.json'
$evidenceFull=Join-Path $env:CA_CONTRACT_ROOT 'explicit-evidence.json'
if($env:CA_PREPARED_PATHS -ceq 'False'){$auditPath=$null;$evidenceFull=$null}
$canonicalWriterFencePreparedPath=Join-Path $env:CA_CONTRACT_ROOT 'absent.json'
$runId='416';$enteredPlacementTry=$false;$canonicalWriterFenceActive=$false;$Script:CanonicalPreparationAdmissionFailed=$false;$Script:CanonicalInstallerSourceInventorySha256=''
$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false
$retirementResume=$null;$old=@()
function Read-ContainerWriterFence {param([switch]$AllowAbsent) return $null}
function Abort-ContainerWriterFence {throw 'host mutation prohibited'}
$original=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('PRIVATE_DETAIL_MUST_NOT_APPEAR'),'FIXTURE_FAILURE',[Management.Automation.ErrorCategory]::InvalidOperation,$null)
try{Invoke-Expression $early[0].Extent.Text}catch{}
if(-not $auditPath){$auditPath=@(Get-ChildItem -LiteralPath $env:LOCALAPPDATA -Recurse -Filter 'canonical-portable-*.json')[0].FullName}
$record=Get-Content -LiteralPath $auditPath -Raw|ConvertFrom-Json
if($record.status -cne 'FAILED' -or $record.preparation_status -cne 'FAILED_PREPARATION_ADMISSION' -or $record.code_placement -cne 'NOT_STARTED' -or $record.rollback.applied -or $record.rollback.status -cne 'NOT_REQUIRED'){throw 'failed admission audit differs'}
if($evidenceFull -and (Get-FileHash $auditPath).Hash -cne (Get-FileHash $evidenceFull).Hash){throw 'explicit evidence differs'}
if((Get-Content -LiteralPath $auditPath -Raw) -match 'PRIVATE_DETAIL_MUST_NOT_APPEAR'){throw 'private error leaked'}
''', engine=engine, values={'CA_PREPARED_PATHS':str(prepared_paths),'LOCALAPPDATA':str(tmp_path/'localappdata')})
    assert result.returncode == 0
    assert result.stdout.count('install_status=FAILED') == 1
    assert 'PRIVATE_DETAIL_MUST_NOT_APPEAR' not in result.stdout + result.stderr


@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
def test_uncaught_preparation_failure_uses_fixed_public_message(tmp_path, engine):
    from tests.powershell_contracts import run_functions
    source = Path(__file__).resolve().parents[1]/'INSTALL_CANONICAL_PORTABLE.ps1'
    result = run_functions(tmp_path, source, ['Full','Get-CanonicalFailureDetails','Write-CanonicalPreparationAdmissionFailure'], r'''
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'failure.json';$evidenceFull=$null
$enteredPlacementTry=$false;$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false;$Script:CanonicalPreparationAdmissionFailed=$false;$Script:CanonicalInstallerSourceInventorySha256=''
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$null,[ref]$null)
$boundary=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[-1]
try{throw [InvalidOperationException]::new('PRIVATE_ADMISSION_DETAIL_MUST_STAY_PRIVATE')}
catch{Invoke-Expression ('& '+$boundary.CatchClauses[0].Body.Extent.Text)}
''', engine=engine)
    assert result.returncode != 0
    assert result.stdout.count('install_status=FAILED') == 1
    assert 'FAILED_PREPARATION_ADMISSION' in result.stderr
    assert 'InvalidOperation' in result.stderr
    assert 'PRIVATE_ADMISSION_DETAIL_MUST_STAY_PRIVATE' not in result.stdout + result.stderr
    audit = json.loads((tmp_path/'failure.json').read_bytes())
    assert audit['status'] == 'FAILED'
    assert audit['preparation_status'] == audit['preparation_failure']['code'] == 'FAILED_PREPARATION_ADMISSION'


@pytest.mark.parametrize('engine', ('powershell.exe','pwsh.exe'))
@pytest.mark.parametrize('refuse', (False, True))
def test_source_admission_wrapper_is_quiet_on_success_and_audits_once(tmp_path, engine, refuse):
    from tests.powershell_contracts import run_functions
    source = Path(__file__).resolve().parents[1]/'INSTALL_CANONICAL_PORTABLE.ps1'
    result = run_functions(tmp_path, source, ['Full','Get-CanonicalFailureDetails','Write-CanonicalPreparationAdmissionFailure','Invoke-ContainerSourceDataAdmission'], r'''
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'admission.json';$evidenceFull=$null
$enteredPlacementTry=$false;$Uninstall=$false;$RestoreVerifiedReplacement=$false;$CompleteRetiredRemoval=$false
$Script:CanonicalPreparationAdmissionFailed=$false;$Script:CanonicalInstallerSourceInventorySha256=('a'*64)
function Get-CanonicalOnboardingInputBinding {
 param($Root,$InstallerSourceInventorySha256)
 if($Root -cne $env:CA_CONTRACT_ROOT -or $InstallerSourceInventorySha256 -cne ('a'*64)){throw 'binding differs'}
 if($env:CA_REFUSE -ceq 'True'){throw [InvalidOperationException]::new('PRIVATE_WRAPPER_DETAIL')}
 return ('b'*64)
}
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CA_CONTRACT_SOURCE,[ref]$null,[ref]$null)
$boundary=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[-1]
try{Invoke-ContainerSourceDataAdmission $env:CA_CONTRACT_ROOT ('a'*64) $auditPath $evidenceFull}
catch{try{Invoke-Expression ('& '+$boundary.CatchClauses[0].Body.Extent.Text)}catch{if($_.Exception.Message -cne 'FAILED_PREPARATION_ADMISSION'){throw 'public failure differs'}}}
if($env:CA_REFUSE -cne 'True'){
 if($Script:canonicalOnboardingInputBinding -cne ('b'*64) -or (Test-Path $auditPath)){throw 'success wrote admission state'}
}else{
 $record=Get-Content -LiteralPath $auditPath -Raw|ConvertFrom-Json
 if($record.status -cne 'FAILED' -or $record.source_inventory_sha256 -cne ('a'*64) -or $record.preparation_failure.exception_types.Count -lt 1){throw 'typed source failure binding differs'}
}
''', engine=engine, values={'CA_REFUSE':str(refuse)})
    assert result.returncode == 0
    assert result.stdout.count('install_status=FAILED') == int(refuse)
    assert 'PRIVATE_WRAPPER_DETAIL' not in result.stdout + result.stderr
    if refuse:
        assert 'PRIVATE_WRAPPER_DETAIL' not in (tmp_path/'admission.json').read_text()
    else:
        assert not result.stdout.strip()

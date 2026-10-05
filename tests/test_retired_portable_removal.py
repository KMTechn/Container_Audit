"""Retirement completion preserves the old stop request across exact removal."""
from __future__ import annotations

import io
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

from tests.test_canonical_portable_uninstall import HELPER_OS, ROOT, _install, _launch_relay, _ps, _setup, _sha, _tree
from tests.powershell_contracts import run_functions

OLD_COMMIT = 'd69dd303c8829132b02971473d8093e024e8b6dd'


def _expected_evidence_tree(root, before, result, *, claimant=False):
    """Add only this observed run/PID's exact 3115733 diagnostic artifacts."""
    observation = result.fixture_audit
    assert observation is not None
    audit = Path(observation['audit_path'])
    assert audit.name == 'canonical-portable-' + observation['run_id'] + '.json'
    assert type(observation['process_id']) is int and observation['process_id'] > 0
    directory = Path(str(audit) + '.evidence.' + str(observation['process_id']))
    assert directory.resolve().is_relative_to(root.resolve())
    stages = directory / 'stages.jsonl'
    expected_paths = {stages}
    rows = [json.loads(line) for line in stages.read_text(encoding='utf-8-sig').splitlines()]
    originals = {row['original_failure']['path']: row['original_failure']
                 for row in rows if row.get('event') == 'CAUGHT_FAILURE'}
    assert len(originals) == int(claimant)
    for name, record in originals.items():
        path = Path(name)
        assert path.parent == directory
        assert path.name.startswith('original-failure-') and path.suffix == '.json'
        assert len(path.stem.removeprefix('original-failure-')) == 32
        assert record['status'] == 'PRESERVED' and record['complete'] is True
        assert _sha(path) == record['sha256']
        assert path.stat().st_size == record['saved_bytes'] <= record['byte_cap']
        payload = json.loads(path.read_bytes())
        assert payload['schema'] == 'container-audit-original-installation-failure-v1'
        assert payload['complete'] is True and payload['truncated'] is False
        expected_paths.add(path)
    if claimant:
        expected_paths.add(directory / 'evidence-status.json')
    assert {p for p in directory.rglob('*') if p.is_file()} == expected_paths
    assert rows and all(isinstance(row, dict) for row in rows)
    assert rows[0]['event'] == 'INITIALIZED'
    assert rows[0]['process_id'] == observation['process_id']
    assert any(row.get('stage') == 'canonical.writer_fence_preflight' for row in rows)
    if claimant:
        assert any(row.get('event') == 'END' and row.get('result') == 'FAILED' for row in rows)
        assert any(row.get('lane') == 'rollback' for row in rows)
        summary = json.loads((directory / 'evidence-status.json').read_text(encoding='utf-8-sig'))
        assert summary['root'] == str(directory) and summary['summary_written'] is True
    expected = dict(before)
    for path in expected_paths:
        relative = str(path.relative_to(root))
        assert relative not in expected
        expected[relative] = _sha(path)
    return expected


def _retired_fixture(tmp_path, fault='', *, historical=False):
    env, old_source, install, protected = _setup(tmp_path, fault)
    manager = tmp_path / 'manager'
    shutil.copytree(old_source, manager)
    if historical:
        def committed(relative):
            return subprocess.run(['git', 'show', OLD_COMMIT + ':' + relative],
                                  cwd=ROOT, capture_output=True, check=True).stdout
        for relative in (
            'INSTALL_CANONICAL_PORTABLE.ps1', 'INSTALL_THIS_PC.ps1',
            'tools/bootstrap_integrity.ps1', 'tools/container_writer_fence.ps1',
            'tools/container_writer_session.ps1', 'tools/container_writer_session_contract.json',
            'tools/container_writer_sink_inventory.json',
        ):
            payload = committed(relative)
            if relative == 'INSTALL_THIS_PC.ps1':
                # d69 predates 3115733 evidence APIs. Keep precisely its original
                # OS seams; the current protected-journal seam has no old consumer.
                historical_os = HELPER_OS.split('# Only OS protection is simulated;')[0]
                payload = payload.decode('utf-8-sig').replace(
                    '$testOverride = (', historical_os + '\n$testOverride = (').encode('utf-8-sig')
            elif relative == 'tools/container_writer_fence.ps1':
                payload = payload.replace(b'Local\\KMTech.ContainerAudit.WriterAdmission.v1',
                                          env['CA_UNINSTALL_MUTEX'].encode())
            (old_source / relative).write_bytes(payload)
            (install / relative).write_bytes(payload)
        manifest_path = old_source / 'portable-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['source_commit'] = OLD_COMMIT
        for field, relative in (
            ('installer', 'INSTALL_CANONICAL_PORTABLE.ps1'), ('helper', 'INSTALL_THIS_PC.ps1'),
            ('integrity_helper', 'tools/bootstrap_integrity.ps1'),
            ('writer_fence_helper', 'tools/container_writer_fence.ps1'),
            ('writer_session_adapter', 'tools/container_writer_session.ps1'),
            ('writer_session_contract', 'tools/container_writer_session_contract.json'),
            ('writer_sink_inventory', 'tools/container_writer_sink_inventory.json'),
        ):
            manifest[field + '_sha256'] = _sha(old_source / relative)
        manifest['writer_sink_inventory_contract_sha256'] = json.loads(
            (old_source / 'tools/container_writer_sink_inventory.json').read_text())['inventory_sha256']
        files = [p for p in old_source.rglob('*') if p.is_file() and p != manifest_path]
        manifest['file_count_before_manifest'] = len(files)
        manifest['byte_count_before_manifest'] = sum(p.stat().st_size for p in files)
        manifest_path.write_text(json.dumps(manifest))
        (install / 'portable-manifest.json').write_bytes(manifest_path.read_bytes())
        recorded = _ps(tmp_path / 'record.ps1', env)
        assert recorded.returncode == 0, recorded.stderr
        legacy_python = tmp_path / 'legacy-python'
        legacy_python.mkdir()
        # The historical producer and every runtime dependency must match its
        # helper. Four old modules plus today's producer form no real release.
        tracked = subprocess.run(['git', 'ls-tree', '-r', '--name-only', OLD_COMMIT],
                                 cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
        runtime_paths = [path for path in tracked if '/' not in path and path.endswith('.py')]
        runtime_paths += ['config', 'kmtech_shared', 'kmtech_factory_contracts',
                          'vendor', 'tools', 'portable']
        archive = subprocess.run(['git', 'archive', '--format=zip', OLD_COMMIT, *runtime_paths],
                                 cwd=ROOT, capture_output=True, check=True).stdout
        with zipfile.ZipFile(io.BytesIO(archive)) as runtime:
            for member in runtime.infolist():
                assert (legacy_python / member.filename).resolve().is_relative_to(legacy_python.resolve())
            runtime.extractall(legacy_python)
        host = Path(env['CA_UNINSTALL_HOST'])
        host.write_text(host.read_text().replace(
            "sys.path.insert(0, os.environ['CA_UNINSTALL_REPO'])",
            "sys.path.insert(0, os.environ['CA_UNINSTALL_REPO'])\n"
            + 'sys.path.insert(0, ' + repr(str(legacy_python)) + ')\n'
            + 'import importlib.util\n'
            + "for name in ('writer_session_fence', 'current_user_onboarding', 'user_relay', "
              "'storage_policy', 'container_audit_product_host'):\n"
            + '    assert Path(importlib.util.find_spec(name).origin).parent == Path('
            + repr(str(legacy_python)) + ')',
        ), encoding='utf-8')
    retire = tmp_path / 'retire.ps1'
    retire.write_text(
        '& $env:CA_UNINSTALL_PYTHON -I -B $env:CA_UNINSTALL_HOST remove '
        + "'" + str(install / 'app').replace("'", "''") + "'\nexit $LASTEXITCODE\n",
        encoding='utf-8-sig',
    )
    result = _ps(retire, env)
    assert result.returncode == 0, result.stderr
    legacy = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit'
    receipt = legacy / 'status/current_user_removal.json'
    marker = legacy / 'control/container_audit_user_relay.stop.json'
    assert receipt.is_file() and marker.is_file()
    adopted = tmp_path / 'adopted'
    adopted.mkdir()
    env['CONTAINER_AUDIT_DATA_ROOT'] = str(adopted)
    host = Path(env['CA_UNINSTALL_HOST'])
    host.write_text(host.read_text().replace(
        "direct = Path(os.environ['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit'",
        "direct = (Path(os.environ['CONTAINER_AUDIT_DATA_ROOT']) / 'direct_sync' "
        "if os.environ.get('CONTAINER_AUDIT_DATA_ROOT') else "
        "Path(os.environ['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit')",
    ), encoding='utf-8')
    command = subprocess.list2cmdline([
        str(install / 'runtime/pythonw.exe'), '-I', '-B', str(install / 'app/main.py'),
        '--container-audit-user-relay', '--data-root', str(adopted),
    ])
    (tmp_path / 'registry.json').write_text(json.dumps({'exists': True, 'kind': 'String', 'data': command}))
    env['CA_UNINSTALL_LAUNCH_COMMAND'] = command
    for relative in ('events/current.json', 'parked_trays/held.json', 'direct_sync/queue/pending.json'):
        path = adopted / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'preserve-order-quantity-and-pending-identity')
        protected.append(path)
    manifest_path = manager / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['source_commit'] = 'c' * 40
    manifest_path.write_text(json.dumps(manifest))
    return env, old_source, manager, install, protected, receipt, marker


def _complete(tmp_path, env, old_source, manager, install, receipt, marker, **pins):
    resume = []
    if pins.get('resume_path'):
        resume = ['-ResumeRetirementReceiptPath', str(pins['resume_path']),
                  '-ResumeRetirementReceiptSha256', pins.get('resume_pin', _sha(pins['resume_path']))]
    return _ps(manager / 'INSTALL_CANONICAL_PORTABLE.ps1', env,
               '-SourceRoot', str(manager), '-InstallRoot', str(install),
               '-CompleteRetiredRemoval', '-OldSourceRoot', str(old_source),
               '-RetiredRemovalReceiptSha256', pins.get('receipt_pin', _sha(receipt)),
               '-RetiredStopMarkerSha256', pins.get('marker_pin', _sha(marker)),
               '-EvidencePath', str(pins.get('evidence_path', tmp_path / 'retirement-audit.json')),
               '-AllowNoncanonicalLayoutForTest', '-SkipSignatureValidationForTest', *resume)


@pytest.mark.parametrize('live', [False, True])
def test_retired_exact_old_code_removal_preserves_retirement_and_data(tmp_path, live):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path)
    original = {p: p.read_bytes() for p in [*protected, receipt, marker]}
    if live:
        with _launch_relay(tmp_path, env) as relay:
            result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
            relay.wait(timeout=10)
            assert not (tmp_path / 'relay.ready').exists()
    else:
        result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not install.exists()
    assert all(p.read_bytes() == content for p, content in original.items())
    audit = json.loads((tmp_path / 'retirement-audit.json').read_text(encoding='utf-8-sig'))
    assert audit['status'] == 'PASS_RETIRED_REMOVAL_DATA_PRESERVED'
    assert audit['retirement']['stop_marker_preserved'] is True
    assert not json.loads((tmp_path / 'registry.json').read_text())['exists']
    assert not (Path(env['CONTAINER_AUDIT_DATA_ROOT']) / 'direct_sync/control/container_audit_user_relay.stop.json').exists()


@pytest.mark.parametrize('difference', ['request', 'marker_pin', 'receipt_pin', 'code', 'active_root'])
def test_retirement_rejects_unbound_or_active_prestate_without_mutation(tmp_path, difference):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path)
    pins = {}
    if difference == 'request':
        payload = json.loads(marker.read_text())
        payload['request_id'] = 'a' * 32
        marker.write_text(json.dumps(payload))
    elif difference in {'marker_pin', 'receipt_pin'}:
        pins[difference] = 'b' * 64
    elif difference == 'code':
        main = install / 'app/main.py'
        main.write_bytes(main.read_bytes().replace(b'#', b'X', 1))
    else:
        env['CONTAINER_AUDIT_DATA_ROOT'] = str(Path(env['LOCALAPPDATA']) / 'KMTech/ContainerAudit')
    original = {p: p.read_bytes() for p in [*protected, receipt, marker, tmp_path / 'registry.json']}
    before = _tree(install)
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker, **pins)
    assert result.returncode != 0
    assert 'RETIREMENT_' in result.stderr or 'integrity' in result.stderr.lower()
    assert _tree(install) == before
    assert all(p.read_bytes() == content for p, content in original.items())
    assert not (Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control/writer-session/active.json').exists()


@pytest.mark.parametrize('fault', ['forged', 'partial', 'after_removal', 'fence_release'])
def test_retirement_failure_restores_exact_code_run_and_retired_marker(tmp_path, fault):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path, fault)
    original = {p: p.read_bytes() for p in [*protected, receipt, marker]}
    registry_before = json.loads((tmp_path / 'registry.json').read_text())
    before = _tree(install)
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
    assert result.returncode != 0
    assert 'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY' in result.stdout
    assert _tree(install) == before
    assert all(p.read_bytes() == content for p, content in original.items())
    assert json.loads((tmp_path / 'registry.json').read_text(encoding='utf-8-sig')) == registry_before
    assert not (Path(env['CONTAINER_AUDIT_DATA_ROOT']) / 'direct_sync/control/container_audit_user_relay.stop.json').exists()


@pytest.mark.parametrize('fault', ['restore_failure', 'partial_foreign', 'partial_damaged'])
def test_retirement_failed_code_recovery_still_restores_run_and_records_every_tail(tmp_path, fault):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path, fault)
    preserved = {p: p.read_bytes() for p in [*protected, receipt, marker]}
    registry = json.loads((tmp_path / 'registry.json').read_text())
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
    assert result.returncode != 0
    assert 'PASS_EXACT_PREIMAGE_SAFE_TO_RETRY' not in result.stdout
    assert json.loads((tmp_path / 'registry.json').read_text(encoding='utf-8-sig')) == registry
    assert all(p.read_bytes() == content for p, content in preserved.items())
    audit = json.loads((tmp_path / 'retirement-audit.json').read_text(encoding='utf-8-sig'))
    steps = {row['step']: row['status'] for row in audit['rollback']['steps']}
    assert steps == {'delegation': 'PROVEN', 'code': 'FAILED', 'retired_pair': 'PROVEN',
                     'relay_identity': 'PROVEN', 'run_preimage': 'PROVEN', 'stop_preimage': 'PROVEN',
                     'fence_release': 'FAILED', 'old_relay': 'FAILED'}
    control = Path(env['LOCALAPPDATA']) / 'KMTech/DirectSync/container_audit/control/writer-session/active.json'
    assert control.is_file() and audit['rollback']['code_exact'] is False
    assert audit['status'] == 'RETIREMENT_ROLLBACK_INCOMPLETE_FENCED'
    if fault == 'partial_foreign':
        assert (install / 'unknown.txt').read_text() == 'preserve-unknown'
    elif fault == 'partial_damaged':
        assert (install / 'app/Container_Audit.py').read_text() == 'changed-known-file'


def test_retirement_first_child_diagnostic_is_complete_and_masks_environment_value(tmp_path):
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1',
                           ['Get-CanonicalRetirementChildFailure'], r'''
$ErrorActionPreference='Stop'
. (Join-Path $env:CA_CONTRACT_SOURCE_ROOT 'tools\bootstrap_integrity.ps1')
$name='CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN'
$synthetic=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
$prior=[Environment]::GetEnvironmentVariable($name,'Process')
try {
    [Environment]::SetEnvironmentVariable($name,$synthetic,'Process')
    $long=('first-cause-'*800)+'END_FIRST_CAUSE'
    $child=[pscustomobject]@{ProcessId=123;ExitCode=73;Stdout=($long+"`n"+$synthetic);Stderr=($synthetic+"`n"+$long);Streams=@{}}
    $failure=Get-CanonicalRetirementChildFailure $child -Environment @{$name=$synthetic}
    $summary=$failure|ConvertTo-Json -Depth 12 -Compress
    $path=Join-Path $env:CA_CONTRACT_ROOT 'failure-audit.json'
    [IO.File]::WriteAllText($path,$summary,[Text.UTF8Encoding]::new($false))
    if ($summary.Contains($synthetic) -or [IO.File]::ReadAllText($path).Contains($synthetic)) {throw 'SECRET_RAW_VALUE_RETAINED'}
    if ($failure.stdout -cne ($long+"`n[REDACTED:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN]") -or $failure.stderr -cne ("[REDACTED:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN]`n"+$long)) {throw 'FIRST_DIAGNOSTIC_TRUNCATED'}
    'PASS_COMPLETE_REDACTED'
} finally {[Environment]::SetEnvironmentVariable($name,$prior,'Process')}
''', values={'CA_CONTRACT_SOURCE_ROOT': str(ROOT)})
    assert result.returncode == 0, 'complete redacted retirement diagnostic contract failed'
    assert result.stdout.strip() == 'PASS_COMPLETE_REDACTED'


def test_retirement_first_child_failure_survives_recovery_and_contains_no_raw_secret(tmp_path):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path, 'diagnostic')
    before = _tree(install)
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
    assert result.returncode != 0
    assert 'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY' in result.stdout
    assert _tree(install) == before
    audit_path = tmp_path / 'retirement-audit.json'
    failure = json.loads(audit_path.read_text(encoding='utf-8-sig'))['retirement_child_failure']
    full_cause = 'first-cause-' * 800 + 'END_FIRST_CAUSE[REDACTED:CONTAINER_AUDIT_WRITER_DELEGATION_TOKEN]'
    raw = env['CA_UNINSTALL_SYNTHETIC'].encode()
    safe = all(raw not in payload for payload in (result.stdout.encode(), result.stderr.encode(), audit_path.read_bytes()))
    assert safe, 'secret present in guidance/summary/audit (value suppressed)'
    observation = result.fixture_audit
    directory = Path(observation['audit_path'] + '.evidence.' + str(observation['process_id']))
    assert all(raw not in p.read_bytes() for p in directory.rglob('*') if p.is_file()), 'secret in evidence (value suppressed)'
    full_present = full_cause in failure['stdout'] and full_cause in result.stdout
    assert full_present, 'first child diagnostic missing or truncated (output suppressed)'


@pytest.mark.parametrize('operation', ['install', 'ordinary_remove', 'update'])
def test_general_finally_still_persists_installation_evidence(tmp_path, operation):
    # Execute the actual finally consumer, independently of native authority
    # admission (which remains a separate non-elevated UNPROVEN positive).
    result = run_functions(tmp_path, ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1', ['Sha'], r'''
$ErrorActionPreference='Stop'
$block=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and
    $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('$finalEvidence=Complete-InstallationEvidence')},$true))
if($block.Count -ne 1){throw 'canonical finally not unique'}
$Uninstall=($env:CA_FINAL_OPERATION -ceq 'ordinary_remove');$CompleteRetiredRemoval=$false
$retirementAuditSealed=$false;$original=$null
$audit=@{rollback=@{runtime_restored=$true}}
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'audit.json';$evidenceFull=''
$canonicalWriterFenceEnvironmentNames=@();$canonicalWriterFenceAuthority=$null
$retirementResumeClaim=$null;$continuationOldClaim=$null
function Complete-InstallationEvidenceStage {}
function Complete-InstallationEvidence {return @{status='COMPLETE';summary_written=$true}}
function Save($Path,$Value) {[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 12))}
function Exit-RetirementResumeClaim {}
$body=$block[0].Finally.Extent.Text
. ([scriptblock]::Create($body.Substring(1,$body.Length-2))) | Out-Null
$stored=Get-Content -LiteralPath $auditPath -Raw | ConvertFrom-Json
if(-not $stored.installation_evidence.summary_written -or $stored.installation_evidence.status -cne 'COMPLETE'){throw 'general final evidence missing'}
'PASS'
''', values={'CA_FINAL_OPERATION': operation})
    assert result.returncode == 0 and result.stdout.strip() == 'PASS'


def test_new_canonical_install_after_retirement_reuses_adopted_identity(tmp_path):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path)
    host = Path(env['CA_UNINSTALL_HOST'])
    host.write_text(host.read_text().replace(
        "elif sys.argv[1] == 'remove':",
        "elif sys.argv[1] == 'prepare':\n"
        "    from tests.test_current_user_onboarding import _ready_state\n"
        "    paths = onboarding.resolve_current_user_onboarding_paths(sys.argv[2])\n"
        "    _ready_state(paths)\n"
        "    onboarding._create_ledger(paths.ledger_path)\n"
        "elif sys.argv[1] == 'remove':",
    ).replace(
        "        _ready_state(paths)\n        return 0",
        "        raise AssertionError('retirement must not enroll again')",
    ), encoding='utf-8')
    prepare = tmp_path / 'prepare.ps1'
    prepare.write_text(
        '& $env:CA_UNINSTALL_PYTHON -I -B $env:CA_UNINSTALL_HOST prepare '
        + "'" + str(install / 'app').replace("'", "''") + "'\nexit $LASTEXITCODE\n",
        encoding='utf-8-sig',
    )
    prepared = _ps(prepare, env)
    assert prepared.returncode == 0, prepared.stderr
    adopted = Path(env['CONTAINER_AUDIT_DATA_ROOT'])
    original = {p: p.read_bytes() for p in [*protected, receipt, marker]}
    # Include every prepared identity/profile/credential/ledger file; observation
    # reports and relay control are lifecycle output, not business preimages.
    original.update({p: p.read_bytes() for p in adopted.rglob('*') if p.is_file()})
    with _launch_relay(tmp_path, env):
        removed = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
        assert removed.returncode == 0, removed.stdout + removed.stderr
        installed = _install(tmp_path, env, manager, install)
        assert installed.returncode == 0, installed.stdout + installed.stderr
        onboarding = json.loads((adopted / 'direct_sync/status/current_user_onboarding.json').read_text())
        assert onboarding['status'] == 'READY'
        assert onboarding['action'] == 'REUSED'
        assert all(p.read_bytes() == content for p, content in original.items())


def test_retirement_uses_historical_d69_helper_and_guard_without_rewriting_old_packet(tmp_path):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path, historical=True)
    before = _tree(old_source)
    original = {p: p.read_bytes() for p in [*protected, receipt, marker]}
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not install.exists()
    assert _tree(old_source) == before
    assert all(p.read_bytes() == content for p, content in original.items())


@pytest.mark.parametrize('difference', ['active_marker', 'other_user_root', 'code_data_overlap', 'evidence_marker'])
def test_retirement_rejects_foreign_requests_and_overlapping_output_before_mutation(tmp_path, difference):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path)
    pins = {}
    if difference == 'active_marker':
        active = Path(env['CONTAINER_AUDIT_DATA_ROOT']) / 'direct_sync/control/container_audit_user_relay.stop.json'
        active.parent.mkdir(parents=True)
        active.write_bytes(marker.read_bytes())
    elif difference == 'other_user_root':
        value = json.loads(receipt.read_text())
        value['preserved_paths'][0] = str(tmp_path / 'other-user/KMTech/ContainerAudit')
        receipt.write_text(json.dumps(value))
    elif difference == 'code_data_overlap':
        env['CONTAINER_AUDIT_DATA_ROOT'] = str(old_source / 'app')
    else:
        pins['evidence_path'] = marker
    original = _tree(tmp_path)
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker, **pins)
    assert result.returncode != 0
    assert 'RETIREMENT_' in result.stderr or 'CANONICAL_STOP_MARKER_PREEXISTS' in result.stderr
    expected = (_expected_evidence_tree(tmp_path, original, result)
                if difference == 'active_marker' else original)
    assert _tree(tmp_path) == expected


@pytest.mark.parametrize('bound', [True, False])
def test_retirement_marker_does_not_prove_external_packet_writer_stopped(tmp_path, bound):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path)
    script = manager / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = script.read_text(encoding='utf-8-sig')
    needle = "    return CimCmdlets\\Get-CimInstance @PSBoundParameters"
    assert text.count(needle) == 1
    text = text.replace(needle,
        "    if ($ClassName -ceq 'Win32_Process' -and -not $Filter) {\n"
        "        return [pscustomobject]@{ ProcessId=1; ExecutablePath=$env:CA_UNINSTALL_PYTHON; "
        "CommandLine=($env:CA_UNINSTALL_PYTHON + ' -I -B ' + $env:CA_RETIREMENT_EXTERNAL_SCRIPT) }\n"
        "    }\n" + needle)
    script.write_text(text, encoding='utf-8-sig')
    manifest_path = manager / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['installer_sha256'] = _sha(script)
    manifest['byte_count_before_manifest'] = sum(p.stat().st_size for p in manager.rglob('*') if p.is_file() and p != manifest_path)
    manifest_path.write_text(json.dumps(manifest))
    if bound:
        env['CA_RETIREMENT_EXTERNAL_SCRIPT'] = str(old_source / 'app/main.py')
    else:
        unrelated = tmp_path / 'another-packet/app/main.py'
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text('# unrelated dataset\n')
        env['CA_RETIREMENT_EXTERNAL_SCRIPT'] = str(unrelated) + ' --container-audit-direct-sync-relay'
    original = {p: p.read_bytes() for p in [*protected, receipt, marker]}
    code = _tree(install)
    before = json.loads((tmp_path / 'registry.json').read_text())
    result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
    if bound:
        assert result.returncode != 0
        assert 'RETIREMENT_CODE_WRITER_STILL_ACTIVE' in result.stderr
        assert 'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY' in result.stdout
        assert _tree(install) == code
        assert json.loads((tmp_path / 'registry.json').read_text(encoding='utf-8-sig')) == before
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert not install.exists()
    assert all(p.read_bytes() == content for p, content in original.items())


@pytest.mark.parametrize('retirement', [False, True])
def test_fresh_removal_requires_its_own_stop_marker_before_code_removal(tmp_path, retirement):
    if retirement:
        env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path)
    else:
        env, old_source, install, protected = _setup(tmp_path)
    host = Path(env['CA_UNINSTALL_HOST'])
    needle = "    raise SystemExit(dispatch_product_mode(['--remove-current-user-setup', '--app-root', sys.argv[2]]))"
    text = host.read_text()
    assert text.count(needle) == 1
    host.write_text(text.replace(needle,
        "    result = dispatch_product_mode(['--remove-current-user-setup', '--app-root', sys.argv[2]])\n"
        "    user_relay.user_relay_stop_path(direct).unlink()\n"
        "    raise SystemExit(result)"), encoding='utf-8')
    before = _tree(install)
    original = {p: p.read_bytes() for p in protected}
    if retirement:
        original.update({p: p.read_bytes() for p in (receipt, marker)})
        result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
    else:
        result = _ps(old_source / 'INSTALL_CANONICAL_PORTABLE.ps1', env,
                     '-SourceRoot', str(old_source), '-InstallRoot', str(install), '-Uninstall',
                     '-AllowNoncanonicalLayoutForTest', '-SkipSignatureValidationForTest')
    assert result.returncode != 0
    assert _tree(install) == before
    assert all(p.read_bytes() == content for p, content in original.items())


@pytest.mark.parametrize('ending',['failure','natural_exit'])
def test_sealed_finally_keeps_bytes_and_records_evidence(tmp_path,ending):
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',['Sha'],r'''
function Set-InstallationEvidenceAcl {}
$block=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('$finalEvidence=Complete-InstallationEvidence')},$true))
if($block.Count -ne 1){throw 'finally not unique'}
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'audit.json';$evidenceFull=''
[IO.File]::WriteAllText($auditPath,'sealed-exact-audit',[Text.UTF8Encoding]::new($false))
$pin=Sha $auditPath
$root=Initialize-InstallationEvidence $auditPath 'S-1-5-21-111-222-333-1001'
Set-InstallationEvidenceStage 'retirement.release_authorized'
$retirementAuditSealed=$true;$CompleteRetiredRemoval=$true;$Uninstall=$true
$audit=@{rollback=@{runtime_restored=$false}};$original=$null
if($env:CA_ENDING -ceq 'failure'){
 try{throw 'POST_SEAL_FAILURE'}catch{$original=$_;Fail-InstallationEvidenceStages $_}
 Set-InstallationEvidenceStage 'rollback.retirement' 'rollback'
}else{Write-InstallationEvidenceEvent ([ordered]@{event='FIXTURE_CONTROLLER_EXIT';exit_code=97})}
$canonicalWriterFenceEnvironmentNames=@();$canonicalWriterFenceAuthority=$null
$retirementResumeClaim=$null;$continuationOldClaim=$null
function Save($Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 12))}
function Exit-RetirementResumeClaim {}
$body=$block[0].Finally.Extent.Text
. ([scriptblock]::Create($body.Substring(1,$body.Length-2)))|Out-Null
if((Sha $auditPath) -cne $pin){throw 'SEALED_BYTES_CHANGED'}
$rows=@(Get-Content -LiteralPath (Join-Path $root 'stages.jsonl')|ForEach-Object{$_|ConvertFrom-Json})
if($env:CA_ENDING -ceq 'failure'){
 if(@($rows|Where-Object{$_.event -ceq 'CAUGHT_FAILURE' -and $_.failure.exception_chain[0].message -match 'POST_SEAL_FAILURE'}).Count -ne 1){throw 'failure absent'}
 if(@($rows|Where-Object{$_.event -ceq 'END' -and $_.result -ceq 'FAILED'}).Count -ne 2){throw 'forward/rollback failure absent'}
}else{
 if(@($rows|Where-Object{$_.event -ceq 'FIXTURE_CONTROLLER_EXIT' -and $_.exit_code -eq 97}).Count -ne 1){throw 'exit absent'}
 if(@($rows|Where-Object{$_.event -ceq 'END' -and $_.stage -ceq 'retirement.release_authorized'}).Count -ne 1){throw 'exit stage absent'}
}
$expectedCount=2
if($env:CA_ENDING -ceq 'failure'){
 $originalFiles=@(Get-ChildItem -LiteralPath $root -File -Filter 'original-failure-*.json')
 if($originalFiles.Count -ne 1){throw 'original evidence not unique'}
 $reference=@($rows|Where-Object{$_.event -ceq 'CAUGHT_FAILURE'})[0].original_failure
 if($reference.path -cne $originalFiles[0].FullName -or $reference.sha256 -cne (Sha $originalFiles[0].FullName) -or -not $reference.complete){throw 'original evidence binding differs'}
 $expectedCount=3
}
if(@(Get-ChildItem -LiteralPath $root -File).Count -ne $expectedCount){throw 'evidence count differs'}
'PASS'
''',values={'CA_ENDING':ending})
    assert result.returncode==0 and result.stdout.strip()=='PASS','sealed finally/evidence consumer failed'

@pytest.mark.parametrize('fault', ['partial', 'after_removal'])
def test_retirement_exact_recovery_restarts_the_preexisting_live_relay(tmp_path, fault):
    env, old_source, manager, install, protected, receipt, marker = _retired_fixture(tmp_path, fault)
    original = {p: p.read_bytes() for p in [*protected, receipt, marker]}
    registry = json.loads((tmp_path / 'registry.json').read_text())
    before = _tree(install)
    with _launch_relay(tmp_path, env) as relay:
        first_pid = relay.pid
        result = _complete(tmp_path, env, old_source, manager, install, receipt, marker)
        assert result.returncode != 0
        assert 'uninstall_recovery_status=PASS_EXACT_PREIMAGE_SAFE_TO_RETRY' in result.stdout
        relay.wait(timeout=10)
        assert (tmp_path / 'relay.ready').is_file()
        launches = [json.loads(line) for line in (tmp_path / 'relay-launches.jsonl').read_text().splitlines()]
        assert len(launches) == 2
        assert launches[0]['ProcessId'] == first_pid and launches[1]['ProcessId'] != first_pid
        assert launches[1]['fence_active'] is False
        assert _tree(install) == before
        assert json.loads((tmp_path / 'registry.json').read_text(encoding='utf-8-sig')) == registry
        assert all(p.read_bytes() == content for p, content in original.items())
        audit = json.loads((tmp_path / 'retirement-audit.json').read_text(encoding='utf-8-sig'))
        assert len(audit['rollback']['steps']) == 8
        assert all(row['status'] == 'PROVEN' for row in audit['rollback']['steps'])
        assert audit['rollback']['runtime_restored'] is True


@pytest.mark.parametrize('sealed',[False,True])
def test_common_catch_preserves_seal_and_records_unsealed_failure(tmp_path,sealed):
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',['Sha','Get-CanonicalFailureDetails'],r'''
function Set-InstallationEvidenceAcl {}
$main=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('$finalEvidence=Complete-InstallationEvidence')},$true))
if($main.Count -ne 1){throw 'main catch not unique'}
$statements=$main[0].CatchClauses[0].Body.Statements
$placement=@($statements|Where-Object{$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -ceq '$enteredPlacementTry'})
if($placement.Count -ne 1){throw 'placement catch not unique'}
$auditPath=Join-Path $env:CA_CONTRACT_ROOT 'audit.json';$evidenceFull=''
[IO.File]::WriteAllText($auditPath,'sealed-audit-bytes',[Text.UTF8Encoding]::new($false));$pin=Sha $auditPath
$root=Initialize-InstallationEvidence $auditPath 'S-1-5-21-111-222-333-1001'
Set-InstallationEvidenceStage 'retirement.release_authorized'
$retirementAuditSealed=($env:CA_SEALED -ceq 'True');$CompleteRetiredRemoval=$retirementAuditSealed
$audit=@{rollback=@{runtime_restored=$false}};$enteredPlacementTry=$true
function Save($Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 12))}
try{throw 'POST_SEAL_CAUGHT_FAILURE'}catch{
 $initial=$_
 # Execute the real catch prefix through rollback.entry; output hardening added
 # statements before the evidence calls, so positional slices are obsolete.
 $prefix=@()
 foreach($statement in $statements){
  if([object]::ReferenceEquals($statement,$placement[0])){break}
  $prefix+=,$statement
 }
 if(@($prefix|Where-Object{$_.Extent.Text -ceq 'Fail-InstallationEvidenceStages $original'}).Count -ne 1){throw 'failure evidence call not unique'}
 if(@($prefix|Where-Object{$_.Extent.Text -ceq "Set-InstallationEvidenceStage 'rollback.entry' 'rollback'"}).Count -ne 1){throw 'rollback stage call not unique'}
 foreach($statement in $prefix){. ([scriptblock]::Create($statement.Extent.Text))}
 foreach($statement in @($placement[0].Clauses[0].Item2.Statements|Select-Object -First 3)){. ([scriptblock]::Create($statement.Extent.Text))}
 if(-not [object]::ReferenceEquals($original,$initial)){throw 'original exception replaced'}
}
if($retirementAuditSealed){if((Sha $auditPath) -cne $pin){throw 'SEALED_CATCH_BYTES_CHANGED'}}
else{
 $saved=Get-Content -LiteralPath $auditPath -Raw|ConvertFrom-Json
 if(-not $saved.failure -or $saved.failure_type -cne $original.Exception.GetType().Name){throw 'GENERAL_CATCH_FAILURE_MISSING'}
}
$rows=@(Get-Content -LiteralPath (Join-Path $root 'stages.jsonl')|ForEach-Object{$_|ConvertFrom-Json})
if(@($rows|Where-Object{$_.event -ceq 'CAUGHT_FAILURE' -and $_.failure.exception_chain[0].message -ceq 'POST_SEAL_CAUGHT_FAILURE'}).Count -ne 2){throw 'post-seal evidence failure missing'}
if(@($rows|Where-Object{$_.event -ceq 'END' -and $_.result -ceq 'FAILED' -and $_.stage -ceq 'retirement.release_authorized'}).Count -ne 1){throw 'post-seal failed stage missing'}
'PASS'
''',values={'CA_SEALED':str(sealed)})
    assert result.returncode==0 and result.stdout.strip()=='PASS','actual catch audit/evidence consumer failed'

@pytest.mark.parametrize('case',['enabled','unrecognized','noncanonical_disabled'])
def test_retirement_rejects_legacy_writers_without_disabled_transition_proof(tmp_path,case):
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',['Sha','Assert-CanonicalRetiredLegacyWriterAdmission'],r'''
$CompleteRetiredRemoval=$true;$Uninstall=$true;$RestoreVerifiedReplacement=$false
$installationEvidenceRoot=$env:CA_CONTRACT_ROOT
$writerBefore=@{present=($env:CA_TASK_CASE -cne 'noncanonical_disabled');enabled=($env:CA_TASK_CASE -ceq 'enabled');task_name='synthetic-unknown';task_path='\';noncanonical_disabled=@()}
if($env:CA_TASK_CASE -ceq 'noncanonical_disabled'){$writerBefore.noncanonical_disabled=@(@{task_name='synthetic-unknown';task_path='\'})}
$nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.Contains('$retirementLegacyWriterAdmission=Assert-CanonicalRetiredLegacyWriterAdmission')},$true)|Sort-Object {$_.Extent.Text.Length})
if(-not $nodes.Count){throw 'legacy retirement consumer absent'}
$rejected=$false
try{. ([scriptblock]::Create($nodes[0].Extent.Text))}catch{$rejected=$_.Exception.Message -ceq 'Uninstall/restore requires the current-user layout without legacy scheduled writers.'}
if(-not $rejected){throw 'UNKNOWN_OR_ENABLED_LEGACY_ADMITTED'}
'PASS'
''',values={'CA_TASK_CASE':case})
    assert result.returncode==0 and result.stdout.strip()=='PASS','legacy writer rejection consumer failed'

def test_retirement_without_legacy_writers_needs_no_common_identity_supplier(tmp_path):
    result=run_functions(tmp_path,ROOT/'INSTALL_CANONICAL_PORTABLE.ps1',
                         ['Assert-CanonicalRetiredLegacyWriterAdmission'],r'''
$snapshot=[ordered]@{present=$false;classification='TEST_BYPASS';restore_required=$false}
$proofs=@(Assert-CanonicalRetiredLegacyWriterAdmission $snapshot $env:CA_CONTRACT_ROOT)
if($proofs.Count -ne 0){throw 'absent legacy writers gained authority'}
'PASS'
''')
    assert result.returncode==0 and result.stdout.strip()=='PASS'

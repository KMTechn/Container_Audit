"""Owned administrator admission, placement, pending and first-start contracts."""

from pathlib import Path
import shutil
import json

import pytest

from tests.powershell_contracts import run_powershell, run_functions


INSTALLER = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_canonical_binds_explicit_worker_account_without_running_installer(tmp_path, engine):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required for executable argument contracts")
    source = str(INSTALLER).replace("'", "''")
    driver = tmp_path / "worker-argument.ps1"
    # Execute only the product's actual binder. The installation body, helpers,
    # identity lookup, profile reads, UAC, and all writers remain unexecuted.
    driver.write_text(
        "$ErrorActionPreference='Stop'\n"
        "$tokens=$null; $errors=$null\n"
        f"$ast=[Management.Automation.Language.Parser]::ParseFile('{source}',"
        "[ref]$tokens,[ref]$errors)\n"
        "if($errors.Count){throw 'product PowerShell parse failed'}\n"
        "$binder=[scriptblock]::Create('[CmdletBinding()]'+\"`n\"+"
        "$ast.ParamBlock.Extent.Text+\"`n'BOUND'\")\n"
        "& $binder -WorkerAccount 'S-1-5-21-111-222-333-1001'\n",
        encoding="utf-8-sig",
    )
    result = run_powershell(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver)]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "BOUND"


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("scenario", (
    "ready", "no_args", "no_inventory", "no_account", "same_sid", "missing_file",
    "invalid_json", "not_ready", "other_sid", "other_profile", "ordinary_args", "ordinary",
))
def test_worker_inventory_admission_is_read_only(tmp_path, engine, scenario):
    result = run_functions(tmp_path, INSTALLER,
        ["Full", "Same", "Resolve-CanonicalWorkerSid", "Resolve-CanonicalMachineWorker"], r'''
$profile=Join-Path $env:CA_CONTRACT_ROOT 'worker'
$other=Join-Path $env:CA_CONTRACT_ROOT 'administrator'
[void][IO.Directory]::CreateDirectory($profile)
[void][IO.Directory]::CreateDirectory($other)
[IO.File]::WriteAllText((Join-Path $profile 'legacy-data.txt'),'old worker data')
[IO.File]::WriteAllText((Join-Path $other 'admin-data.txt'),'old administrator data')
function Get-CanonicalWorkerProfileRoot {param($Sid) return $profile}
$caller=[pscustomobject]@{sid='S-1-5-21-111-222-333-1000';session_id=0;elevated=$true}
$account='S-1-5-21-111-222-333-1001'
$path=Join-Path $env:CA_CONTRACT_ROOT 'survey.json'
$inventory=@{status='READY';target_sid=$account;target_profile_root=$profile}
switch($env:CA_SCENARIO){
 'no_args'{$account='';$path=''}
 'no_inventory'{$path=''}
 'no_account'{$account=''}
 'same_sid'{$account=$caller.sid;$inventory.target_sid=$account}
 'not_ready'{$inventory.status='PENDING'}
 'other_sid'{$inventory.target_sid='S-1-5-21-111-222-333-1002'}
 'other_profile'{$inventory.target_profile_root=$other}
 'ordinary_args'{$caller.session_id=1;$caller.elevated=$false}
 'ordinary'{$caller.session_id=1;$caller.elevated=$false;$account='';$path=''}
}
if($path -and $env:CA_SCENARIO -cne 'missing_file'){
 $text=if($env:CA_SCENARIO -ceq 'invalid_json'){'{invalid'}else{$inventory|ConvertTo-Json}
 [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))
}
$before=@(Get-ChildItem -LiteralPath $env:CA_CONTRACT_ROOT -Recurse -File | ForEach-Object { $_.FullName+':'+(Get-FileHash -LiteralPath $_.FullName).Hash })
$accepted=$false;$value=$null
try{$value=Resolve-CanonicalMachineWorker $account $path $caller;$accepted=$true}catch{}
$wanted=$env:CA_SCENARIO -cin @('ready','ordinary')
if($accepted -ne $wanted){throw 'worker inventory admission differs'}
if($env:CA_SCENARIO -ceq 'ready'){
 if($value.sid -cne $inventory.target_sid -or $value.survey_sha256 -cne (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()){throw 'admitted identity/digest differs'}
}
if($env:CA_SCENARIO -ceq 'ordinary' -and $null -ne $value){throw 'ordinary route changed'}
$after=@(Get-ChildItem -LiteralPath $env:CA_CONTRACT_ROOT -Recurse -File | ForEach-Object { $_.FullName+':'+(Get-FileHash -LiteralPath $_.FullName).Hash })
if(Compare-Object $before $after){throw 'admission wrote files'}
'PASS'
''', engine=engine, values={"CA_SCENARIO": scenario})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def machine_intent(tmp_path):
    from current_user_onboarding import consume_pending_machine_onboarding

    root = tmp_path / "current"
    app = root / "app"
    app.mkdir(parents=True)
    manifest = {"source_commit": "a" * 40, "version": "v2.0.102"}
    (root / "portable-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    program_data = tmp_path / "program"
    marker = program_data / "KMTech/ContainerAudit/machine-install/pending-onboarding.json"
    marker.parent.mkdir(parents=True)
    payload = {"schema": "container-audit-machine-pending-v1", "status": "PENDING",
               "install_id": "b" * 32, "target_sid": "S-1-5-21-111-222-333-1001",
               "install_root": str(root), **manifest}
    marker.write_text(json.dumps(payload), encoding="utf-8")
    completed = []
    calls = []
    def run(_app, **kwargs):
        calls.append(kwargs)
        return {"status": "READY", "action": "registered"}
    def consume(**overrides):
        options = {"environ": {"PROGRAMDATA": str(program_data)}, "onboarder": run,
                   "sid_reader": lambda: payload["target_sid"],
                   "completion_reader": lambda: completed[-1] if completed else "",
                   "completion_writer": completed.append}
        options.update(overrides)
        return consume_pending_machine_onboarding(app, **options)
    return marker, payload, calls, completed, consume


def test_worker_first_start_finishes_once_and_leaves_read_only_intent(machine_intent):
    marker, _, calls, completed, consume = machine_intent
    before = marker.read_bytes()
    assert consume()["status"] == "READY"
    assert consume()["action"] == "MACHINE_INSTALL_ALREADY_COMPLETED"
    assert len(calls) == len(completed) == 1
    assert calls[0]["require_bootstrap_integrity"] is True
    assert marker.read_bytes() == before


def test_other_sid_does_not_onboard_or_mark_complete(machine_intent):
    from current_user_onboarding import CurrentUserOnboardingError
    marker, _, calls, completed, consume = machine_intent
    before = marker.read_bytes()
    with pytest.raises(CurrentUserOnboardingError) as failure:
        consume(sid_reader=lambda: "S-1-5-21-111-222-333-1002")
    assert failure.value.status == "PENDING_WORKER_SID_MISMATCH"
    assert not calls and not completed
    assert marker.read_bytes() == before


def test_failed_onboarding_is_retryable_and_never_claims_completion(machine_intent):
    from current_user_onboarding import CurrentUserOnboardingError
    marker, _, calls, completed, consume = machine_intent
    before = marker.read_bytes()
    with pytest.raises(CurrentUserOnboardingError):
        consume(onboarder=lambda *_args, **_kwargs: {"status": "FAILED"})
    assert not completed
    assert marker.read_bytes() == before
    assert consume()["status"] == "READY"
    assert len(calls) == len(completed) == 1


def test_reinstallation_has_a_new_completion_id(machine_intent):
    marker, payload, calls, completed, consume = machine_intent
    consume()
    payload["install_id"] = "c" * 32
    marker.write_text(json.dumps(payload), encoding="utf-8")
    consume()
    assert completed == ["b" * 32, "c" * 32]
    assert len(calls) == 2


def test_stale_release_intent_does_not_onboard(machine_intent):
    from current_user_onboarding import CurrentUserOnboardingError
    marker, payload, calls, completed, consume = machine_intent
    payload["source_commit"] = "d" * 40
    marker.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CurrentUserOnboardingError):
        consume()
    assert not calls and not completed


def test_completed_install_does_not_block_later_release(machine_intent):
    marker, _, calls, _, consume = machine_intent
    consume()
    before = marker.read_bytes()
    manifest = marker.parents[3].parent / "current/portable-manifest.json"
    manifest.write_text(json.dumps({"source_commit": "e" * 40, "version": "v2.0.103"}), encoding="utf-8")
    assert consume()["action"] == "MACHINE_INSTALL_ALREADY_COMPLETED"
    assert len(calls) == 1 and marker.read_bytes() == before


def test_retained_machine_fence_does_not_onboard_or_complete(machine_intent):
    from current_user_onboarding import CurrentUserOnboardingError
    marker, _, calls, completed, consume = machine_intent
    active = marker.parent / "control/writer-session/active.json"
    active.parent.mkdir(parents=True)
    active.write_text("{}", encoding="utf-8")
    before = marker.read_bytes()
    with pytest.raises(CurrentUserOnboardingError):
        consume()
    assert not calls and not completed and marker.read_bytes() == before


@pytest.mark.parametrize("managed", (True, False))
def test_first_start_accepts_only_current_or_exact_managed_release(machine_intent, managed):
    from current_user_onboarding import consume_pending_machine_onboarding, CurrentUserOnboardingError
    marker, payload, calls, completed, _ = machine_intent
    install = Path(payload["install_root"])
    runtime = install.parent / ("versions" if managed else "unrelated") / payload["source_commit"]
    (runtime / "app").mkdir(parents=True)
    (runtime / "portable-manifest.json").write_bytes((install / "portable-manifest.json").read_bytes())
    before = marker.read_bytes()
    def run(*_args, **_kwargs):
        calls.append(True)
        return {"status": "READY"}
    def consume():
        return consume_pending_machine_onboarding(
            runtime / "app", environ={"PROGRAMDATA": str(marker.parents[3])}, onboarder=run,
            sid_reader=lambda: payload["target_sid"], completion_reader=lambda: "", completion_writer=completed.append,
        )
    if managed:
        assert consume()["status"] == "READY" and len(calls) == len(completed) == 1
    else:
        with pytest.raises(CurrentUserOnboardingError): consume()
        assert not calls and not completed
    assert marker.read_bytes() == before


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("no_account", "no_inventory", "same_sid", "not_ready", "other_sid", "other_profile", "invalid_json"))
def test_public_machine_admission_denial_has_one_line_and_zero_writes(tmp_path, engine, case):
    from tests.test_zero_touch_installer import _portable_release_fixture
    from tests.test_canonical_portable_uninstall import _tree
    from tests.native_process_fixtures import native_python_environment

    executable = shutil.which(engine)
    assert executable is not None, f"required engine missing: {engine}"
    source = _portable_release_fixture(tmp_path)
    worker = tmp_path / "worker"
    worker.mkdir()
    (worker / "old-app.txt").write_bytes(b"preserve legacy bytes")
    local = tmp_path / "admin-local"
    local.mkdir()
    program = tmp_path / "program"
    program.mkdir()
    inventory = tmp_path / "survey.json"
    sid = "S-1-5-21-111-222-333-1001"
    payload = {"status": "READY", "target_sid": sid, "target_profile_root": str(worker)}
    if case == "not_ready": payload["status"] = "INCOMPLETE"
    if case == "other_sid": payload["target_sid"] = "S-1-5-21-111-222-333-1002"
    if case == "other_profile": payload["target_profile_root"] = str(local)
    inventory.write_text("{" if case == "invalid_json" else json.dumps(payload), encoding="utf-8")
    canonical = source / "INSTALL_CANONICAL_PORTABLE.ps1"
    text = canonical.read_text(encoding="utf-8-sig")
    caller = r'''
function Get-CanonicalInstallationCallerSecurity {
 return [pscustomobject]@{sid='S-1-5-21-111-222-333-1000';session_id=0;elevated=$true}
}
function Get-CanonicalWorkerProfileRoot {param($Sid) return $env:CA_MACHINE_PROFILE}
'''
    admission = "# Admit the worker before any installation evidence, authority or profile writer."
    canonical.write_text(text.replace(admission, caller + "\n" + admission), encoding="utf-8-sig")
    env = native_python_environment()
    env.update(LOCALAPPDATA=str(local), PROGRAMDATA=str(program), CA_MACHINE_PROFILE=str(worker),
               KMTECH_FACTORY_INSTALL_TEST_MODE="1")
    arguments = []
    if case != "no_account": arguments += ["-WorkerAccount", "S-1-5-21-111-222-333-1000" if case == "same_sid" else sid]
    if case != "no_inventory": arguments += ["-WorkerSurveyInventory", str(inventory)]
    before = _tree(tmp_path)
    result = run_powershell([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(canonical),
                            "-SourceRoot", str(source), "-InstallRoot", str(tmp_path / "owned/current"),
                            "-EvidencePath", str(tmp_path / "must-not-exist.json"),
                            "-AllowNoncanonicalLayoutForTest", *arguments], env=env)
    assert result.returncode == 4 and not result.stderr
    lines = result.stdout.splitlines()
    assert len(lines) == 1 and lines[0].startswith("CONTAINER_AUDIT_INSTALL_CANONICAL=")
    assert json.loads(lines[0].split("=", 1)[1])["code"] == "PENDING_TARGET_AMBIGUOUS"
    assert _tree(tmp_path) == before


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_actual_common_shortcut_target_is_rejected_by_legacy_candidate_reader(tmp_path, engine):
    # Reader from the reviewed kit v251106 Legacy-Survey.ps1, SHA256
    # 46a96899996a27875391b65b9257837a352269f8aff7a9ac054c098139a0762e.
    # Only this exact EXE-name admission is frozen; no host discovery runs.
    driver = r'''
function Resolve-KmtechLegacyPath([string]$Path) {return [IO.Path]::GetFullPath($Path)}
function Read-KmtechLegacySurveyCandidate([string]$Path,[string]$Source) {
    $path=Resolve-KmtechLegacyPath $Path
    if([IO.Path]::GetFileName($path) -inotin @('Container_Audit.exe','Label_Match.exe') -or -not (Test-Path -LiteralPath $path -PathType Leaf)){throw '옛 앱 후보의 실제 실행 파일을 확인하지 못했습니다.'}
    $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    return @{path=$path;name=$file.Name;bytes=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;sources=@($Source)}
}
function ConvertTo-ProcessArgument([string]$Value) {return '"'+$Value+'"'}
$script:link=[pscustomobject]@{TargetPath='';Arguments='';WorkingDirectory=''}
$script:link | Add-Member ScriptMethod Save {
 [IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'captured-shortcut.json'),($this|ConvertTo-Json))
}
$script:shell=[pscustomobject]@{}
$script:shell | Add-Member ScriptMethod CreateShortcut {param($Path);return $script:link}
function New-Object {param($ComObject);if($ComObject -cne 'WScript.Shell'){throw 'unexpected COM consumer'};return $script:shell}
# Adapt only COM release/known-folder readback to the owned shortcut capture.
# The product sets all target, argument and working-directory properties.
$body=${function:New-CanonicalMachineShortcut}.ToString().Replace('[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)','')
$body=$body.Replace('[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)', '(Join-Path $env:CA_CONTRACT_ROOT ''common-programs'')')
$body=$body.Replace('if (-not (Test-Path -LiteralPath $path -PathType Leaf))', 'if (-not (Test-Path -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT ''captured-shortcut.json'') -PathType Leaf))')
Set-Item Function:New-CanonicalMachineShortcut ([scriptblock]::Create($body))
$root=Join-Path $env:CA_CONTRACT_ROOT 'current'
[void][IO.Directory]::CreateDirectory((Join-Path $root 'runtime'))
[IO.File]::WriteAllText((Join-Path $root 'runtime\pythonw.exe'),'owned runtime double')
$legacy=Join-Path $env:CA_CONTRACT_ROOT 'Container_Audit.exe'
[IO.File]::WriteAllText($legacy,'owned legacy double')
New-CanonicalMachineShortcut $root
if($script:link.TargetPath -cne (Join-Path $root 'runtime\pythonw.exe')){throw 'common target differs'}
if($script:link.Arguments -cne ('-I -B "'+(Join-Path $root 'app\main.py')+'"')){throw 'common arguments differ'}
if((Read-KmtechLegacySurveyCandidate $legacy 'fixture').name -cne 'Container_Audit.exe'){throw 'legacy positive control lost'}
$rejected=$false
try{[void](Read-KmtechLegacySurveyCandidate $script:link.TargetPath 'shortcut')}catch{$rejected=$true}
if(-not $rejected){throw 'new shortcut became a legacy candidate'}
'COMMON_SHORTCUT_LEGACY_EXCLUSION_PASS'
'''
    result = run_functions(tmp_path, INSTALLER, ["New-CanonicalMachineShortcut"], driver, engine=engine)
    assert result.returncode == 0, result.stderr
    assert "COMMON_SHORTCUT_LEGACY_EXCLUSION_PASS" in result.stdout


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("first_start", (False, True))
def test_machine_placement_existing_restore_and_removal_preserve_profiles(tmp_path, engine, first_start):
    from tests.test_canonical_portable_uninstall import _setup, _tree, _sha, OS_BOUNDARIES, HELPER_OS
    from tests.test_canonical_installation_callers import _distinct_replacement, _bind_packet
    from current_user_onboarding import consume_pending_machine_onboarding

    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required")
    env, source, installed, protected = _setup(tmp_path, stock_version_identity=True)
    old_commit = json.loads((installed / "portable-manifest.json").read_text())["source_commit"]
    _distinct_replacement(source)  # Preserve actual placement/delegation validation.
    worker = tmp_path / "worker-profile"
    worker.mkdir()
    (worker / "legacy-data.txt").write_text("legacy worker data", encoding="utf-8")
    inventory = tmp_path / "worker-survey.json"
    sid = "S-1-5-21-111-222-333-1001"
    inventory.write_text(json.dumps({"status": "READY", "target_sid": sid,
                                     "target_profile_root": str(worker)}), encoding="utf-8")
    canonical = source / "INSTALL_CANONICAL_PORTABLE.ps1"
    text = canonical.read_text(encoding="utf-8-sig")
    text = text.replace(OS_BOUNDARIES + "\n", "")
    protection = HELPER_OS[HELPER_OS.index("# Only OS protection is simulated;"):]
    # Synthetic caller/ProfileList and owned scheduler/ACL boundaries only;
    # the actual entrypoint, admission, placement, inventory and receipts run.
    injected = OS_BOUNDARIES + "\n$UninstallAuditPath=Join-Path $env:CA_UNINSTALL_ROOT 'machine-audit.json'\n" + protection + r'''
function Get-CanonicalInstallationCallerSecurity {
 return [pscustomobject]@{sid='S-1-5-21-111-222-333-1000';session_id=0;elevated=$true}
}
function Get-CanonicalWorkerProfileRoot {param($Sid) return $env:CA_MACHINE_PROFILE}
function New-CanonicalMachineShortcut {param($Root)
 [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'machine-shortcut.json'),
   (@{target=(Join-Path $Root 'runtime\pythonw.exe');arguments='-I -B app\main.py'}|ConvertTo-Json))
}
'''
    admission = "# Admit the worker before any installation evidence, authority or profile writer."
    assert text.count(admission) == 1
    canonical.write_text(text.replace(admission, injected + "\n" + admission), encoding="utf-8-sig")
    text = canonical.read_text(encoding="utf-8-sig")
    diagnostic = "[IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'machine-error.json'),(@{details=(Get-CanonicalFailureDetails $_ 'MACHINE_FIXTURE');stack=$_.ScriptStackTrace}|ConvertTo-Json -Depth 8));"
    text = text.replace("Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED';", diagnostic + "Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED';")
    canonical.write_text(text, encoding="utf-8-sig")
    env["CA_MACHINE_PROFILE"] = str(worker)
    _bind_packet(source)
    profiles_before = (_tree(Path(env["LOCALAPPDATA"])), _tree(worker))

    def run(label, *arguments):
        audit = tmp_path / (label + ".json")
        result = run_powershell([
            executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(canonical),
            "-SourceRoot", str(source), "-InstallRoot", str(installed),
            "-WorkerAccount", sid, "-WorkerSurveyInventory", str(inventory),
            "-EvidencePath", str(audit), "-AllowNoncanonicalLayoutForTest", "-SkipSignatureValidationForTest",
            *arguments,
        ], env=env)
        (tmp_path / (label + "-stdout.log")).write_text(result.stdout, encoding="utf-8")
        (tmp_path / (label + "-stderr.log")).write_text(result.stderr, encoding="utf-8")
        assert result.returncode == 0, f"{label}: exit {result.returncode}; evidence in {tmp_path}"
        assert (_tree(Path(env["LOCALAPPDATA"])), _tree(worker)) == profiles_before
        assert all(path.read_bytes() == b"protected-fixture-must-be-preserved" for path in protected)
        return json.loads(audit.read_text(encoding="utf-8"))

    audit = run("machine-install")
    assert audit["status"] == "PASS_MACHINE_WORKER_PENDING"
    assert json.loads((installed / "portable-manifest.json").read_text())["source_commit"] == "c" * 40
    marker = Path(env["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install/pending-onboarding.json"
    marker_before = marker.read_bytes()
    payload = json.loads(marker_before)
    assert payload["survey_sha256"] == _sha(inventory)
    if first_start:
        completed = []
        result = consume_pending_machine_onboarding(
            installed / "app", environ=env, sid_reader=lambda: sid,
            completion_reader=lambda: "", completion_writer=completed.append,
            onboarder=lambda *_args, **_kwargs: {"status": "READY"},
        )
        assert result["status"] == "READY" and completed == [payload["install_id"]]
        assert marker.read_bytes() == marker_before
    receipts = list((Path(env["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install").rglob("replacement-receipt.json"))
    # Production helper seals its receipt in the bound protected run. Guarded
    # transport can retain the requested path; both are the same real schema.
    receipt = Path(audit["code_replacement"]["receipt_path"])
    if not receipt.is_file():
        receipts += list((tmp_path / "protected-removal").rglob("replacement-receipt.json"))
        assert len(receipts) == 1
        receipt = receipts[0]
    restored = run("machine-restore", "-RestoreVerifiedReplacement", "-RestoreReceiptPath", str(receipt),
                   "-RestoreReceiptSha256", _sha(receipt))
    assert restored["status"] == "PASS_RESTORED_VERIFIED"
    assert json.loads((installed / "portable-manifest.json").read_text())["source_commit"] == old_commit
    removed = run("machine-uninstall", "-Uninstall")
    assert removed["status"] == "PASS_UNINSTALLED_DATA_PRESERVED"

"""Owned administrator admission, placement, pending and first-start contracts."""

from pathlib import Path
import shutil
import json
import re

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
function Get-CanonicalConsoleWorkerSecurity {throw 'PENDING_TARGET_AMBIGUOUS'}
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
$wanted=$env:CA_SCENARIO -cin @('ready','same_sid','ordinary')
if($accepted -ne $wanted){throw 'worker inventory admission differs'}
if($env:CA_SCENARIO -cin @('ready','same_sid')){
  if($value.sid -cne $inventory.target_sid -or $value.survey_sha256 -cne (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()){throw 'admitted identity/digest differs'}
  if([bool]$value.same_caller -ne ($env:CA_SCENARIO -ceq 'same_sid')){throw 'caller ownership differs'}
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


@pytest.mark.parametrize("other_sid", (False, True))
def test_portable_pending_target_check_precedes_update_gate_without_worker_writes(
    machine_intent, monkeypatch, other_sid,
):
    import importlib.util
    import sys
    import types
    import auto_update
    import current_user_onboarding as onboarding

    marker, payload, calls, completed, consume = machine_intent
    before = marker.read_bytes()
    shown, gate_calls = [], []
    sid = "S-1-5-21-111-222-333-1002" if other_sid else payload["target_sid"]
    def reject_completion_read():
        pytest.fail("target preflight read worker completion state")
    def check(_root, **options):
        return consume(sid_reader=lambda: sid, completion_reader=reject_completion_read,
                       check_target_only=options["check_target_only"])
    def gate(_root, arguments):
        gate_calls.append(arguments)
        return 20
    monkeypatch.setattr(onboarding, "consume_pending_machine_onboarding", check)
    monkeypatch.setattr(auto_update, "startup_gate", gate)
    monkeypatch.setitem(sys.modules, "Container_Audit", types.SimpleNamespace(
        _show_first_run_onboarding_error=shown.append, main=lambda: pytest.fail("GUI ran"),
    ))
    monkeypatch.setattr(sys, "argv", ["main.py"])
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location(
        "sub62_portable_entrypoint", INSTALLER.parent / "portable/main.py",
    )
    entrypoint = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entrypoint)
    assert entrypoint.main() == (1 if other_sid else 20)
    assert len(gate_calls) == (0 if other_sid else 1)
    assert len(shown) == (1 if other_sid else 0)
    if other_sid:
        assert shown[0].status == "PENDING_WORKER_SID_MISMATCH"
    assert not calls and not completed and marker.read_bytes() == before


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
@pytest.mark.parametrize("case", ("no_account", "no_inventory", "not_ready", "other_sid", "other_profile", "invalid_json"))
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
    _mark_hidden_fixture_directory(program)
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
@pytest.mark.parametrize("existing", ("new", "legacy", "owned"))
def test_actual_common_shortcut_target_is_rejected_by_legacy_candidate_reader(tmp_path, engine, existing):
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
if($env:CA_EXISTING_SHORTCUT -cne 'new'){
 $directory=Join-Path $env:CA_CONTRACT_ROOT 'common-programs'
 [void][IO.Directory]::CreateDirectory($directory)
 $prior=Join-Path $directory 'KMTech 이적 검사.lnk'
 [IO.File]::WriteAllText($prior,'preserve original shortcut bytes')
 $priorSha=(Get-FileHash -LiteralPath $prior).Hash
 $script:link.TargetPath=if($env:CA_EXISTING_SHORTCUT -ceq 'legacy'){$legacy}else{Join-Path $root 'runtime\pythonw.exe'}
 $script:link.Arguments=if($env:CA_EXISTING_SHORTCUT -ceq 'legacy'){'legacy command'}else{'-I -B "'+(Join-Path $root 'app\main.py')+'"'}
 $script:link.WorkingDirectory=if($env:CA_EXISTING_SHORTCUT -ceq 'legacy'){$env:CA_CONTRACT_ROOT}else{Join-Path $root 'app'}
 $rejected=$false
 try{New-CanonicalMachineShortcut $root}catch{$rejected=$true}
 if($rejected -ne ($env:CA_EXISTING_SHORTCUT -ceq 'legacy')){throw 'existing shortcut identity admission differs'}
 if((Get-FileHash -LiteralPath $prior).Hash -cne $priorSha){throw 'existing shortcut bytes changed'}
 if(Test-Path -LiteralPath (Join-Path $env:CA_CONTRACT_ROOT 'captured-shortcut.json')){throw 'existing shortcut was saved'}
 'COMMON_SHORTCUT_PRESTATE_PRESERVED_PASS'
 return
}
New-CanonicalMachineShortcut $root
if($script:link.TargetPath -cne (Join-Path $root 'runtime\pythonw.exe')){throw 'common target differs'}
if($script:link.Arguments -cne ('-I -B "'+(Join-Path $root 'app\main.py')+'"')){throw 'common arguments differ'}
if((Read-KmtechLegacySurveyCandidate $legacy 'fixture').name -cne 'Container_Audit.exe'){throw 'legacy positive control lost'}
$rejected=$false
try{[void](Read-KmtechLegacySurveyCandidate $script:link.TargetPath 'shortcut')}catch{$rejected=$true}
if(-not $rejected){throw 'new shortcut became a legacy candidate'}
'COMMON_SHORTCUT_LEGACY_EXCLUSION_PASS'
'''
    result = run_functions(tmp_path, INSTALLER, ["Full", "Same", "Get-CanonicalMachineShortcutArguments", "New-CanonicalMachineShortcut"], driver,
                           engine=engine, values={"CA_EXISTING_SHORTCUT": existing})
    assert result.returncode == 0, result.stderr
    expected = "COMMON_SHORTCUT_LEGACY_EXCLUSION_PASS" if existing == "new" else "COMMON_SHORTCUT_PRESTATE_PRESERVED_PASS"
    assert expected in result.stdout


def _mark_hidden_fixture_directory(path):
    import ctypes
    import os
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        kernel.GetFileAttributesW.restype = ctypes.c_uint32
        kernel.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        attributes = kernel.GetFileAttributesW(str(path))
        assert attributes != 0xFFFFFFFF
        assert kernel.SetFileAttributesW(str(path), attributes | 2)
        assert kernel.GetFileAttributesW(str(path)) & 2


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("first_start", (False, True, "pending_acl_failure", "shortcut_failure", "audit_failure", "same_sid", "same_sid_failure", "pending_reinstall_failure", "pending_reinstall_restore_failure", "console_worker", "placement_child_failure_new", "placement_child_failure_reinstall", "placement_child_exit_unproven", "pending_reinstall_compensation_child_unproven", "prestate_capture_failure", "fence_publication_failure"))
def test_machine_placement_existing_restore_and_removal_preserve_profiles(tmp_path, engine, first_start):
    from tests.test_canonical_portable_uninstall import _setup, _tree, _sha, OS_BOUNDARIES, HELPER_OS
    from tests.test_canonical_installation_callers import _distinct_replacement, _bind_packet
    from current_user_onboarding import consume_pending_machine_onboarding

    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required")
    env, source, installed, protected = _setup(tmp_path, stock_version_identity=True)
    _mark_hidden_fixture_directory(Path(env["PROGRAMDATA"]))
    old_commit = json.loads((installed / "portable-manifest.json").read_text())["source_commit"]
    if first_start == "placement_child_failure_new":
        assert installed.resolve().is_relative_to(tmp_path.resolve())
        assert not installed.is_symlink() and not installed.is_junction()
        shutil.rmtree(installed)  # Only the explicitly owned fixture code root.
    _distinct_replacement(source)  # Preserve actual placement/delegation validation.
    worker = tmp_path / "worker-profile"
    worker.mkdir()
    _mark_hidden_fixture_directory(worker / "AppData")
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
function Get-CanonicalConsoleWorkerSecurity {
 return [pscustomobject]@{sid=$env:CA_MACHINE_SID;session_id=1}
}
function Get-CanonicalMachineArtifactPaths {param($State)
 return @((Join-Path $State 'pending-onboarding.json'),(Join-Path $env:CA_UNINSTALL_ROOT 'machine-shortcut.json'))
}
function New-CanonicalMachineShortcut {param($Root,[string]$Directory='')
 $path=if($Directory){Join-Path $Directory 'KMTech 이적 검사.lnk'}else{Join-Path $env:CA_UNINSTALL_ROOT 'machine-shortcut.json'}
 [IO.File]::WriteAllText($path,
   (@{TargetPath=(Join-Path $Root 'runtime\pythonw.exe');Arguments=(Get-CanonicalMachineShortcutArguments $Root);
      WorkingDirectory=(Join-Path $Root 'app')}|ConvertTo-Json))
 if($env:CA_MACHINE_FAILURE -cin @('pending_reinstall_failure','pending_reinstall_restore_failure','pending_reinstall_compensation_child_unproven')){
   $active=Join-Path (Split-Path -Parent $Root) 'update-control\active.json'
   [IO.File]::WriteAllText($active,(@{schema='container-audit-startup-update-v1';sha=([string](InstalledManifest $Root $true).source_commit)}|ConvertTo-Json))
   throw 'Simulated post-code-and-pointer failure'
  }
  if($env:CA_MACHINE_FAILURE -ceq 'shortcut_failure'){throw 'Simulated post-shortcut failure'}
 if($Directory -and $env:CA_MACHINE_FAILURE -ceq 'same_sid_failure'){throw 'Simulated worker shortcut failure'}
}
function Start-InstallationTransaction {throw 'Administrator path reached interactive coordinator'}
function Invoke-BootstrapNormalFiniteProducer {throw 'Administrator path reached normal interactive producer'}
function StartRaw {throw 'Administrator path reached Session 0 relay guard'}
function Product {throw 'Administrator path reached deferred onboarding'}
$workerPathsBody=${function:Get-CanonicalWorkerPreparationPaths}.ToString().Replace(
 '[Environment]::GetFolderPath([Environment+SpecialFolder]::$folder,[Environment+SpecialFolderOption]::DoNotVerify)',
 '(Join-Path ([string]$Worker.profile_root) $folder)')
Set-Item Function:Get-CanonicalWorkerPreparationPaths ([scriptblock]::Create($workerPathsBody))
$script:machineShell=[pscustomobject]@{}
$script:machineShell | Add-Member ScriptMethod CreateShortcut {param($Path);return (Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json)}
$removeBody=${function:Remove-CanonicalMachineArtifacts}.ToString().Replace('New-Object -ComObject WScript.Shell','$script:machineShell')
$removeBody=$removeBody.Replace('[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)','')
Set-Item Function:Remove-CanonicalMachineArtifacts ([scriptblock]::Create($removeBody))
'''
    if first_start in ("prestate_capture_failure", "fence_publication_failure"):
        # Instrument the original file body so PSCommandPath retains its real binding.
        capture = "function ConvertTo-CanonicalMachineArtifactJournal($Before) {\n"
        assert text.count(capture) == 1
        text = text.replace(capture, capture +
            "    if ($env:CA_MACHINE_FAILURE -ceq 'prestate_capture_failure') { throw 'Simulated prestate capture failure' }\n")
        publication = "\n        $active=$true\n"
        assert text.count(publication) == 1
        text = text.replace(publication,
            "\n        if ($env:CA_MACHINE_FAILURE -ceq 'fence_publication_failure') { throw 'Simulated post-publication readback failure' }\n        $active=$true\n")
    if first_start == "pending_acl_failure":
        injected += r'''
$pendingAcl=${function:Set-InstallationEvidenceAcl}
function Set-InstallationEvidenceAcl([string]$Path,[string]$OperatorSid) {
 if([IO.Path]::GetFileName($Path) -ceq 'pending-onboarding.json'){throw 'Simulated pending ACL failure'}
 & $pendingAcl $Path $OperatorSid
}
'''
    if first_start == "audit_failure":
        injected += r'''
$saveBody=${function:Save}
function Save([string]$Path,$Value,[bool]$SanitizeDiagnostics=$false) {
 if($Value.status -cin @('PASS_MACHINE_WORKER_PENDING','MACHINE_INSTALL_FAILED')){throw 'Simulated success and failure audit write failure'}
 & $saveBody $Path $Value $SanitizeDiagnostics
}
'''
    if first_start in ("pending_reinstall_restore_failure", "pending_reinstall_compensation_child_unproven"):
        injected += r'''
$realChild=${function:Invoke-InstallationEvidenceChild}
function Invoke-InstallationEvidenceChild([string]$Stage,[string]$File,[string[]]$Arguments,[scriptblock]$OnStarted=$null) {
 if($Stage -ceq 'machine-failure-code-restore' -and $env:CA_MACHINE_FAILURE -cin @('pending_reinstall_restore_failure','pending_reinstall_compensation_child_unproven')){
  if($env:CA_MACHINE_FAILURE -ceq 'pending_reinstall_compensation_child_unproven'){throw 'Simulated unknown compensation child'}
  return [pscustomobject]@{ExitCode=1;Stdout='';Stderr=''}
 }
  return & $realChild $Stage $File $Arguments -OnStarted $OnStarted
}
'''
    if first_start in ("placement_child_failure_new", "placement_child_failure_reinstall", "placement_child_exit_unproven"):
        injected += r'''
$realChild=${function:Invoke-InstallationEvidenceChild}
function Invoke-InstallationEvidenceChild([string]$Stage,[string]$File,[string[]]$Arguments,[scriptblock]$OnStarted=$null) {
  $child=& $realChild $Stage $File $Arguments -OnStarted $OnStarted
 if($Stage -ceq 'machine-placement-helper' -and $env:CA_MACHINE_FAILURE -like 'placement_child_*'){
  if($env:CA_MACHINE_FAILURE -ceq 'placement_child_exit_unproven'){throw 'Simulated unproved child transport'}
  $child.ExitCode=1
 }
 return $child
}
'''
    admission = "# Admit the worker before any installation evidence, authority or profile writer."
    assert text.count(admission) == 1
    canonical.write_text(text.replace(admission, injected + "\n" + admission), encoding="utf-8-sig")
    text = canonical.read_text(encoding="utf-8-sig")
    diagnostic = "[IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'machine-error.json'),(@{details=(Get-CanonicalFailureDetails $_ 'MACHINE_FIXTURE');stack=$_.ScriptStackTrace}|ConvertTo-Json -Depth 8));"
    text = text.replace("Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED';", diagnostic + "Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED';")
    canonical.write_text(text, encoding="utf-8-sig")
    same_caller = first_start in ("same_sid", "same_sid_failure")
    if same_caller:
        sid = sid.rsplit("-", 1)[0] + "-1000"
        inventory.write_text(json.dumps({"status": "READY", "target_sid": sid,
                                         "target_profile_root": str(worker)}), encoding="utf-8")
        local = worker / "AppData/Local"
        local.mkdir(parents=True)
        env["LOCALAPPDATA"] = str(local)
    env["CA_MACHINE_PROFILE"] = str(worker)
    env["CA_MACHINE_SID"] = sid
    env["CA_MACHINE_FAILURE"] = str(first_start)
    _bind_packet(source)
    prior_pending = prior_active = None
    if first_start in ("pending_reinstall_failure", "pending_reinstall_restore_failure", "pending_reinstall_compensation_child_unproven"):
        state = Path(env["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install"
        state.mkdir(parents=True)
        prior_pending = json.dumps({"schema": "container-audit-machine-pending-v1", "status": "PENDING",
            "install_id": "d" * 32, "target_sid": sid, "source_commit": old_commit,
            "version": json.loads((installed / "portable-manifest.json").read_text())["version"],
            "install_root": str(installed)}).encode()
        (state / "pending-onboarding.json").write_bytes(prior_pending)
        control = installed.parent / "update-control"
        control.mkdir()
        prior_active = json.dumps({"schema": "container-audit-startup-update-v1", "sha": old_commit}).encode()
        (control / "active.json").write_bytes(prior_active)
    code_before = _tree(installed)
    profiles_before = (_tree(Path(env["LOCALAPPDATA"])), _tree(worker))
    registry_before = json.loads((tmp_path / "registry.json").read_text(encoding="utf-8"))

    def run(label, *arguments, expected_exit=0):
        audit = tmp_path / (label + ".json")
        result = run_powershell([
            executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(canonical),
            "-SourceRoot", str(source), "-InstallRoot", str(installed),
            *([] if first_start == "console_worker" else ["-WorkerAccount", sid, "-WorkerSurveyInventory", str(inventory)]),
            "-EvidencePath", str(audit), "-AllowNoncanonicalLayoutForTest", "-SkipSignatureValidationForTest",
            *arguments,
        ], env=env)
        (tmp_path / (label + "-stdout.log")).write_text(result.stdout, encoding="utf-8")
        (tmp_path / (label + "-stderr.log")).write_text(result.stderr, encoding="utf-8")
        assert result.returncode == expected_exit, f"{label}: exit {result.returncode}; evidence in {tmp_path}"
        if not same_caller or expected_exit:
            assert (_tree(Path(env["LOCALAPPDATA"])), _tree(worker)) == profiles_before
        assert (worker / "legacy-data.txt").read_text(encoding="utf-8") == "legacy worker data"
        assert all(path.read_bytes() == b"protected-fixture-must-be-preserved" for path in protected)
        return json.loads(audit.read_text(encoding="utf-8")) if expected_exit == 0 else result

    if first_start in ("pending_reinstall_failure", "pending_reinstall_restore_failure", "pending_reinstall_compensation_child_unproven"):
        run("pending-reinstall-failed", expected_exit=4)
        state = Path(env["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install"
        fence = state / "control/writer-session/active.json"
        assert fence.is_file() == (first_start != "pending_reinstall_failure")
        pointer = installed.parent / "update-control/active.json"
        code = json.loads((installed / "portable-manifest.json").read_text())["source_commit"]
        assert json.loads(pointer.read_bytes())["sha"] == code
        marker = state / "pending-onboarding.json"
        assert not (tmp_path / "machine-shortcut.json").exists()
        if first_start in ("pending_reinstall_restore_failure", "pending_reinstall_compensation_child_unproven"):
            assert code == "c" * 40 and not marker.exists()
            audits = [p for p in (state / "install-audit").glob("canonical-portable-*.json")
                      if re.fullmatch(r"canonical-portable-[0-9a-f]{32}\.json", p.name)]
            assert len(audits) == 1
            recovery_audit = audits[0]
            failure = json.loads(recovery_audit.read_bytes())
            assert failure["compensation"]["code_restore"] == "UNPROVEN"
            fence_bytes = fence.read_bytes()
            if first_start == "pending_reinstall_compensation_child_unproven":
                assert failure["compensation_child"]["status"] == "EXIT_UNPROVEN"
                env["CA_MACHINE_FAILURE"] = ""
                assert "process_id" not in failure["compensation_child"]
            # Audit and prestate mismatches are rejected before authority or writes.
            run("recovery-bad-audit", "-RecoverMachineInstallation", "-MachineRecoveryAuditPath", str(recovery_audit),
                "-MachineRecoveryAuditSha256", "0" * 64, expected_exit=4)
            assert fence.read_bytes() == fence_bytes
            journal = Path(failure["machine_prestate"]["path"])
            journal_bytes = journal.read_bytes()
            journal.write_bytes(journal_bytes + b" ")
            run("recovery-bad-prestate", "-RecoverMachineInstallation", "-MachineRecoveryAuditPath", str(recovery_audit),
                "-MachineRecoveryAuditSha256", _sha(recovery_audit), expected_exit=4)
            assert fence.read_bytes() == fence_bytes
            journal.write_bytes(journal_bytes)
            env["CA_MACHINE_FAILURE"] = ""
            recovered = run("recovery-supported", "-RecoverMachineInstallation", "-MachineRecoveryAuditPath", str(recovery_audit),
                            "-MachineRecoveryAuditSha256", _sha(recovery_audit))
            assert recovered["fence_retained"] is False
            assert not fence.exists()
            restored_audit = json.loads(recovery_audit.read_bytes())
            assert restored_audit["compensation_child"]["process_id"] > 0
            assert restored_audit["compensation_child"]["started_at_utc"].endswith("Z")
            assert json.loads((installed / "portable-manifest.json").read_bytes())["source_commit"] == old_commit
            assert pointer.read_bytes() == prior_active and marker.read_bytes() == prior_pending
            assert run("recovery-retry")["status"] == "PASS_MACHINE_WORKER_PENDING"
            assert run("recovery-uninstall", "-Uninstall")["status"] == "PASS_UNINSTALLED_DATA_PRESERVED"
            assert not marker.exists() and not (tmp_path / "machine-shortcut.json").exists()
        else:
            assert code == old_commit and pointer.read_bytes() == prior_active
            assert marker.read_bytes() == prior_pending
            # Product compensation lowered the fence; the real pending reader accepts the old release.
            assert not fence.exists()
            completed = []
            assert consume_pending_machine_onboarding(installed / "app", environ=env,
                sid_reader=lambda: sid, completion_reader=lambda: "", completion_writer=completed.append,
                onboarder=lambda *_args, **_kwargs: {"status": "READY"})["status"] == "READY"
            assert completed == ["d" * 32]
        return
    if first_start in ("prestate_capture_failure", "fence_publication_failure"):
        run("fence-preparation-failed", expected_exit=4)
        state = Path(env["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install"
        fence = state / "control/writer-session/active.json"
        assert not fence.exists()
        assert _tree(installed) == code_before
        assert not (state / "pending-onboarding.json").exists()
        assert not (tmp_path / "machine-shortcut.json").exists()
        audits = [p for p in (state / "install-audit").glob("canonical-portable-*.json")
                  if re.fullmatch(r"canonical-portable-[0-9a-f]{32}\.json", p.name)]
        assert len(audits) == 1
        failure = json.loads(audits[0].read_bytes())
        assert failure["placement_child"]["status"] == "NOT_STARTED"
        if first_start == "fence_publication_failure":
            assert failure["compensation"]["code_restore"] == "PASS"
            assert failure["fence_retained"] is False
            assert Path(failure["machine_prestate"]["path"]).is_file()
        env["CA_MACHINE_FAILURE"] = ""
        assert run("fence-preparation-retry")["status"] == "PASS_MACHINE_WORKER_PENDING"
        assert run("fence-preparation-uninstall", "-Uninstall")["status"] == "PASS_UNINSTALLED_DATA_PRESERVED"
        assert not fence.exists() and not installed.exists()
        return
    if first_start in ("placement_child_failure_new", "placement_child_failure_reinstall", "placement_child_exit_unproven"):
        run("placement-child-failed", expected_exit=4)
        state = Path(env["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install"
        fence = state / "control/writer-session/active.json"
        audits = [p for p in (state / "install-audit").glob("canonical-portable-*.json")
                  if re.fullmatch(r"canonical-portable-[0-9a-f]{32}\.json", p.name)]
        assert len(audits) == 1
        failure = json.loads(audits[0].read_bytes())
        if first_start == "placement_child_exit_unproven":
            assert fence.is_file() and failure["compensation"]["child_exit"] == "UNPROVEN"
            assert failure["placement_child"]["process_id"] > 0
            assert failure["placement_child"]["started_at_utc"].endswith("Z")
            env["CA_MACHINE_FAILURE"] = ""
            recovered = run("unproved-child-recovery-supported", "-RecoverMachineInstallation", "-MachineRecoveryAuditPath", str(audits[0]),
                            "-MachineRecoveryAuditSha256", _sha(audits[0]))
            assert recovered["fence_retained"] is False and not fence.exists()
            assert recovered["recovery_child_exit"] == "PASS"
            assert _tree(installed) == code_before
            assert not (state / "pending-onboarding.json").exists()
            assert not (tmp_path / "machine-shortcut.json").exists()
            return
        assert not fence.exists() and failure["fence_retained"] is False
        assert failure["compensation"]["child_exit"] == "PASS"
        assert failure["compensation"]["code_restore"] == "PASS"
        assert failure["artifact_restore"] == "PASS"
        assert not (state / "pending-onboarding.json").exists()
        assert not (tmp_path / "machine-shortcut.json").exists()
        if first_start == "placement_child_failure_new":
            assert not installed.exists()
        else:
            assert json.loads((installed / "portable-manifest.json").read_bytes())["source_commit"] == old_commit
        env["CA_MACHINE_FAILURE"] = ""
        assert run("child-failure-retry")["status"] == "PASS_MACHINE_WORKER_PENDING"
        assert run("child-failure-uninstall", "-Uninstall")["status"] == "PASS_UNINSTALLED_DATA_PRESERVED"
        assert not fence.exists() and not installed.exists()
        assert not (state / "pending-onboarding.json").exists() and not (tmp_path / "machine-shortcut.json").exists()
        return
    if first_start in ("pending_acl_failure", "shortcut_failure", "audit_failure", "same_sid_failure"):
        failed = run("machine-install-failed", expected_exit=4)
        assert "PASS_MACHINE_WORKER_PENDING" not in failed.stdout
        state = Path(env["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install"
        assert not (state / "control/writer-session/active.json").exists()
        machine_audits = [path for path in (state / "install-audit").glob("canonical-portable-*.json")
                          if re.fullmatch(r"canonical-portable-[0-9a-f]{32}\.json", path.name)]
        assert len(machine_audits) == 1
        assert not (state / "pending-onboarding.json").exists()
        assert not (tmp_path / "machine-shortcut.json").exists()
        assert not list(worker.rglob("*.lnk"))
        assert json.loads((tmp_path / "registry.json").read_text(encoding="utf-8")) == registry_before
        assert json.loads((installed / "portable-manifest.json").read_text())["source_commit"] == old_commit
        if first_start != "audit_failure":
            failure = json.loads(machine_audits[0].read_text(encoding="utf-8"))
            assert failure["status"] == "MACHINE_INSTALL_FAILED" and failure["fence_retained"] is False
            assert failure["artifact_restore"] == "PASS"
            assert failure["code_replacement"]["status"] == "RESTORED_AFTER_FAILURE"
        return
    audit = run("machine-install")
    assert audit["status"] == "PASS_MACHINE_WORKER_PENDING"
    assert audit["placement_child"]["process_id"] > 0
    assert audit["placement_child"]["started_at_utc"].endswith("Z")
    assert json.loads((installed / "portable-manifest.json").read_text())["source_commit"] == "c" * 40
    marker = Path(env["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install/pending-onboarding.json"
    marker_before = marker.read_bytes()
    payload = json.loads(marker_before)
    if first_start != "console_worker":
        assert payload["survey_sha256"] == _sha(inventory)
    if first_start == "console_worker":
        assert payload["target_sid"] == sid and payload["status"] == "PENDING"
        assert not (tmp_path / "relay.ready").exists()
        return
    if first_start == "same_sid":
        assert audit["worker_setup"] == "USER_SCOPE_PREPARED_INTERACTIVE_PENDING"
        assert audit["after"]["observation_status"] == "PREPARED"
        registry = json.loads((tmp_path / "registry.json").read_text(encoding="utf-8"))
        assert registry["exists"] is True and registry["kind"] == "String"
        assert "--container-audit-user-relay" in registry["data"]
        for folder in ("Programs", "DesktopDirectory"):
            shortcut = json.loads((worker / folder / "KMTech 이적 검사.lnk").read_text(encoding="utf-8"))
            assert Path(shortcut["TargetPath"]) == installed / "runtime/pythonw.exe"
        assert (Path(env["LOCALAPPDATA"]) / "KMTech/ContainerAudit/events").is_dir()
        assert not (tmp_path / "relay.ready").exists()
        assert payload["status"] == "PENDING"
        return
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
    assert not marker.exists()
    assert not (tmp_path / "machine-shortcut.json").exists()
    assert json.loads((installed / "portable-manifest.json").read_text())["source_commit"] == old_commit
    if first_start is False:
        run("machine-install-before-removal")
        assert marker.is_file() and (tmp_path / "machine-shortcut.json").is_file()
    removed = run("machine-uninstall", "-Uninstall")
    assert removed["status"] == "PASS_UNINSTALLED_DATA_PRESERVED"
    assert not marker.exists()
    assert not (tmp_path / "machine-shortcut.json").exists()

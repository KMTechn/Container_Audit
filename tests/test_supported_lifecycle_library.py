"""Parity of the old Python classifier and the pinned read-only PS classifier."""
import json
import os
from pathlib import Path
import shutil

import pytest

import auto_update as update
from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]
CASES = ("removed", "register_removed", "legacy", "managed", "rolled_back",
         "control_without_code", "partial_control", "bad_phase", "bad_pointer",
          "bad_key", "missing_task", "bad_stock", "namespace_collision", "data_collision",
          "duplicate_key", "wrong_key_case", "oversized", "broken_json", "nonobject", "numeric_sha", "array_metadata")


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", CASES)
def test_readonly_library_preserves_lifecycle_classification(tmp_path, monkeypatch, engine, case):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required for executable lifecycle contracts")
    managed = tmp_path / "managed"
    fixed, control = managed / "current", managed / "update-control"
    old, new = "1" * 40, "2" * 40
    sid = "-".join(("S", "1", "5", "21", "111", "222", "333", "1001"))
    managed.mkdir()
    operation = "register" if case == "register_removed" else "install"
    if case not in {"removed", "register_removed", "control_without_code", "namespace_collision"}:
        for bundle, commit in ((fixed, old), (managed / "versions" / new, new)):
            (bundle / "app").mkdir(parents=True)
            (bundle / "runtime").mkdir()
            (bundle / "app/main.py").write_bytes(b"# owned layout fixture\n")
            (bundle / "runtime/pythonw.exe").write_bytes(b"owned layout fixture")
            (bundle / "app/update-manifest-key-config.json").write_bytes(b"public configuration fixture")
            (bundle / "portable-manifest.json").write_text(json.dumps({
                "schema": "container-audit-portable-tree-v1", "source_commit": commit,
                "source_tree": "3" * 40, "entrypoint": "runtime/pythonw.exe app/main.py",
            }), encoding="utf-8")
    if case == "namespace_collision":
        fixed.write_bytes(b"owned namespace collision")
    if case not in {"removed", "register_removed", "legacy", "namespace_collision", "data_collision", "bad_stock"}:
        control.mkdir()
        policy = {"schema": "container-audit-startup-update-policy-v1", "operator_sid": sid}
        pointer = {"schema": update.SCHEMA, "sha": new}
        state = {"schema": update.SCHEMA, "phase": "DEFERRED", "candidate_sha": new, "previous_sha": new}
        if case == "bad_phase":
            state["phase"] = "UNRESOLVED"
        if case == "bad_pointer":
            state.update(phase="CONFIRMED", candidate_sha=old)
        if case == "rolled_back":
            state["phase"] = "ROLLED_BACK"
        for name, value in (("policy.json", policy), ("active.json", pointer), ("transition.json", state)):
            if case == "partial_control" and name == "transition.json":
                continue
            (control / name).write_text(json.dumps(value), encoding="utf-8")
    if case == "bad_key":
        (managed / "versions" / new / "app/update-manifest-key-config.json").write_bytes(b"different public configuration fixture")
    if case == "duplicate_key":
        path = control / "policy.json"
        path.write_text(path.read_text(encoding="utf-8")[:-1] + ',"schema":"container-audit-startup-update-policy-v1"}', encoding="utf-8")
    if case == "wrong_key_case":
        policy["SCHEMA"] = policy.pop("schema")
        (control / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    if case == "oversized":
        policy["owned_extra"] = "x" * 1048576
        (control / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    if case == "nonobject":
        (control / "policy.json").write_text("[]", encoding="utf-8")
    if case == "broken_json":
        (control / "policy.json").write_text('{"schema":', encoding="utf-8")
    if case == "numeric_sha":
        pointer["sha"] = int(new)
        (control / "active.json").write_text(json.dumps(pointer), encoding="utf-8")
    if case == "array_metadata":
        policy["owned_extra"] = [None, [], {"a": 1, "b": 1.0}, "2026-10-05T00:00:00Z"]
        (control / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(update, "supported_tasks_absent", lambda root, **kwargs: True)
    monkeypatch.setattr(update, "supported_task_present", lambda *args: case != "missing_task")
    def stock(bundle):
        if case == "bad_stock":
            raise ValueError("owned invalid stock fixture")
        return {}
    monkeypatch.setattr(update, "verify_lifecycle_stock", stock)
    if case == "data_collision":
        monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(fixed))
    before = {p.relative_to(managed).as_posix(): p.read_bytes() for p in managed.rglob("*") if p.is_file()}
    try:
        expected = {"ok": True, "context": update.resolve_lifecycle_context(managed, operation=operation)}
    except ValueError as error:
        # The old installer maps every child rejection to this fixed public
        # error; preserve that consumed contract as well as the decision.
        expected = {"ok": False, "error": update.LIFECYCLE_RECOVERY}
        cause = str(error.__cause__)
    accepted = case in {"removed", "legacy", "managed", "rolled_back", "array_metadata"}
    assert expected["ok"] == accepted, "old classifier fixture must reach its intended decision: " + (cause if not expected["ok"] else case)
    task_xml = tmp_path / "task.xml"
    task_xml.write_text(update.logon_task_xml(app_root=fixed, operator_sid=sid), encoding="utf-8")
    driver = tmp_path / "lifecycle-contract.ps1"
    driver.write_text(r'''
$ErrorActionPreference='Stop'
. $env:CA_LIFECYCLE_LIBRARY
# The same stock/OS observations are isolated in the Python and PS classifiers.
# The actual classification and all control/manifest reads remain product code.
function Get-BootstrapReplacementTreeIdentity {
    if($env:CA_LIFECYCLE_CASE -ceq 'bad_stock'){throw 'owned invalid stock fixture'}
    return [pscustomobject]@{owner_sid=('S-1-'+'5-32-544');access_rules_protected=$true}
}
function Get-ScheduledTask {return @()}
function Export-ScheduledTask {
    param([string]$TaskName,[string]$TaskPath)
    if($env:CA_LIFECYCLE_CASE -ceq 'missing_task'){throw 'owned absent task fixture'}
    if($TaskName -cne $env:CA_LIFECYCLE_TASK_NAME){throw 'task identity differs'}
    return Get-Content -LiteralPath $env:CA_LIFECYCLE_TASK_XML -Raw -Encoding UTF8
}
try{
    $context=Get-BootstrapSupportedLifecycleContext $env:CA_LIFECYCLE_ROOT $env:CA_LIFECYCLE_OPERATION
    @{ok=$true;context=$context}|ConvertTo-Json -Depth 12 -Compress
}catch{@{ok=$false;error=$_.Exception.Message}|ConvertTo-Json -Compress}
''', encoding="utf-8-sig")
    environment = dict(os.environ, CA_LIFECYCLE_LIBRARY=str(ROOT / "tools/bootstrap_integrity.ps1"),
                       CA_LIFECYCLE_ROOT=str(managed), CA_LIFECYCLE_CASE=case,
                       CA_LIFECYCLE_OPERATION=operation, CA_LIFECYCLE_TASK_XML=str(task_xml),
                       CA_LIFECYCLE_TASK_NAME=update.task_name(fixed, sid))
    result = run_powershell([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver)],
                            env=environment, timeout=30)
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout)
    assert actual == expected
    assert {p.relative_to(managed).as_posix(): p.read_bytes() for p in managed.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
def test_readonly_record_equality_preserves_object_order_and_exact_numbers(tmp_path, engine):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required for executable lifecycle contracts")
    from tests.powershell_contracts import run_functions
    large = 10 ** 40
    left = {"a": large, "b": [None, [], {"a": 1, "b": 1.0}]}
    right = {"b": [None, [], {"b": 1.0, "a": 1}], "a": large}
    changed = {**right, "a": large + 1}
    for name, value in (("left", left), ("right", right), ("changed", changed)):
        (tmp_path / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1", [
        "Assert-BootstrapNoReparsePoint", "Get-StrictFullPath", "ConvertFrom-BootstrapLifecycleJsonNode",
        "Read-BootstrapLifecycleJson", "Test-BootstrapLifecycleJsonEqual",
    ], r'''
$a=Read-BootstrapLifecycleJson (Join-Path $env:CA_CONTRACT_ROOT 'left.json')
$b=Read-BootstrapLifecycleJson (Join-Path $env:CA_CONTRACT_ROOT 'right.json')
$c=Read-BootstrapLifecycleJson (Join-Path $env:CA_CONTRACT_ROOT 'changed.json')
if(-not(Test-BootstrapLifecycleJsonEqual $a $b)){throw 'equal records differ'}
if(Test-BootstrapLifecycleJsonEqual $a $c){throw 'changed record admitted'}
if($a['b'].Count -ne 3 -or $null -ne $a['b'][0] -or $a['b'][1].Count -ne 0){throw 'array shape differs'}
'PASS'
''', engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr

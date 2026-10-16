"""Native task spellings preserve ownership without admitting other tasks."""
from pathlib import Path
import json
import subprocess
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest
import auto_update as update
from tests.powershell_contracts import run_functions
from tests.test_lifecycle_task_absence_reason import DRIVER, _interrupted_install

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("Principals/Principal/UserId", "SYSTEM", True),
    ("Principals/Principal/UserId", r"NT AUTHORITY\SYSTEM", True),
    ("Principals/Principal/UserId", "S-1-5-18", True),
    ("Settings/Hidden", "TRUE", True),
    ("Settings/Hidden", "1", True),
    ("Settings/AllowHardTerminate", "FALSE", True),
    ("Settings/AllowHardTerminate", "0", True),
    ("Principals/Principal/UserId", "S-1-5-21-11-22-33-1001", False),
    ("Principals/Principal/UserId", "S-1-5-32-544", False),
    ("Principals/Principal/UserId", "Administrators", False),
    ("Principals/Principal/UserId", "", False),
    ("Principals/Principal/UserId", "missing-account", False),
    ("Principals/Principal/RunLevel", "LeastPrivilege", False),
    ("Settings/Hidden", "false", False),
    ("Settings/Hidden", "2", False),
    ("Settings/Hidden", "", False),
    ("Settings/AllowHardTerminate", "true", False),
    ("Actions/Exec/Command", "unowned.exe", False),
    ("Actions/Exec/Arguments", "-Unexpected", False),
]


def changed_task(fixed, sid, path, value):
    task = ET.fromstring(update.logon_task_xml(app_root=fixed, operator_sid=sid))
    task.find("/".join("{*}" + part for part in path.split("/"))).text = value
    return ET.tostring(task, encoding="unicode")


@pytest.mark.parametrize("path,value,accepted", CASES)
def test_python_consumes_native_task_without_relaxing_ownership(tmp_path, monkeypatch, path, value, accepted):
    observed = changed_task(tmp_path, "S-1-5-21-11-22-33-1001", path, value)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=observed, stderr=""))
    assert update.supported_task_present(tmp_path, "S-1-5-21-11-22-33-1001") is accepted


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_actual_powershell_lifecycle_consumes_native_tasks(tmp_path, engine):
    managed, fixed, sid = _interrupted_install(tmp_path)
    for index, (path, value, accepted) in enumerate(CASES):
        (tmp_path / f"task-{index}.xml").write_text(changed_task(fixed, sid, path, value), encoding="utf-8")
    before = {p.relative_to(managed): p.read_bytes() for p in managed.rglob("*") if p.is_file()}
    library = ROOT / "tools/bootstrap_integrity.ps1"
    names = ["Get-StrictFullPath", "Assert-BootstrapNoReparsePoint", "Get-FileSha256",
             "ConvertFrom-BootstrapLifecycleJsonNode", "Read-BootstrapLifecycleJson",
             "Test-BootstrapLifecycleJsonEqual", "Get-BootstrapStringSha256",
             "ConvertTo-BootstrapPrincipalSid", "Get-BootstrapTaskTriggerIdentityStatus",
             "Get-BootstrapSupportedLifecycleContext"]
    if "function Test-BootstrapTaskReadbackValue" in library.read_text(encoding="utf-8-sig"):
        names.append("Test-BootstrapTaskReadbackValue")
    script = "foreach($caseIndex in 0..18){\n" + DRIVER.replace(". $env:CA_LIFECYCLE_LIBRARY", "")
    script = script.replace("try{\n    $context=", "$env:CA_LIFECYCLE_TASK_XML=Join-Path $env:CA_CONTRACT_ROOT ('task-'+$caseIndex+'.xml')\ntry{\n    $context=") + "\n}"
    result = run_functions(tmp_path, library, names, script, engine=engine,
                           values={"CA_LIFECYCLE_ROOT": str(managed), "CA_LIFECYCLE_CASE": "owned_task",
                                   "CA_LIFECYCLE_TASK_NAME": update.task_name(fixed, sid)})
    (tmp_path / "probe-result.json").write_text(json.dumps({
        "rc": result.returncode, "stdout": result.stdout, "stderr": result.stderr}), encoding="utf-8")
    assert result.returncode == 0, "isolated lifecycle probe failed"
    results = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(results) == len(CASES)
    for actual, (path, value, accepted) in zip(results, CASES):
        assert actual["ok"] is accepted, (path, accepted, actual.get("causes"))
        if accepted:
            assert actual["state"] == "HEALTHY"
        else:
            assert actual["causes"][0] == "lifecycle_task_absence_or_unknown"
    assert {p.relative_to(managed): p.read_bytes() for p in managed.rglob("*") if p.is_file()} == before

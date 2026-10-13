"""IA-02: an interrupted first managed install leaves control records without
the startup task. The read-only classifier must keep refusing that state, but
name the same bounded reason as auto_update.resolve_lifecycle_context."""
import json
import os
from pathlib import Path
import shutil

import pytest

import auto_update as update
from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]
DRIVER = r'''
$ErrorActionPreference='Stop'
. $env:CA_LIFECYCLE_LIBRARY
function Get-BootstrapReplacementTreeIdentity {
    return [pscustomobject]@{owner_sid=('S-1-'+'5-32-544');access_rules_protected=$true}
}
function Get-ScheduledTask {return @()}
function Export-ScheduledTask {
    param([string]$TaskName,[string]$TaskPath)
    switch($env:CA_LIFECYCLE_CASE){
        'missing_task' {throw [Microsoft.PowerShell.Commands.WriteErrorException]::new('owned absent task fixture')}
        'other_task' {return (Get-Content -LiteralPath $env:CA_LIFECYCLE_TASK_XML -Raw -Encoding UTF8).Replace('<Hidden>true</Hidden>','<Hidden>false</Hidden>')}
    }
    if($TaskName -cne $env:CA_LIFECYCLE_TASK_NAME){throw 'task identity differs'}
    return Get-Content -LiteralPath $env:CA_LIFECYCLE_TASK_XML -Raw -Encoding UTF8
}
try{
    $context=Get-BootstrapSupportedLifecycleContext $env:CA_LIFECYCLE_ROOT 'install'
    @{ok=$true;state=[string]$context.lifecycle_state}|ConvertTo-Json -Compress
}catch{
    $causes=@();$inner=$_.Exception.InnerException
    for($depth=0;$null -ne $inner -and $depth -lt 8;$depth++){$causes+=,[string]$inner.Message;$inner=$inner.InnerException}
    @{ok=$false;error=$_.Exception.Message;causes=$causes}|ConvertTo-Json -Compress
}
'''


def _interrupted_install(tmp_path):
    managed = tmp_path / "managed"
    fixed = managed / "current"
    commit = "a" * 40
    sid = "-".join(("S", "1", "5", "21", "11", "22", "33", "1001"))
    for bundle in (fixed, managed / "versions" / commit):
        (bundle / "app").mkdir(parents=True)
        (bundle / "runtime").mkdir()
        (bundle / "app/main.py").write_bytes(b"owned layout fixture")
        (bundle / "runtime/pythonw.exe").write_bytes(b"owned layout fixture")
        (bundle / "app/update-manifest-key-config.json").write_bytes(b"public configuration fixture")
        (bundle / "portable-manifest.json").write_text(json.dumps({
            "schema": "container-audit-portable-tree-v1", "source_commit": commit,
            "entrypoint": "runtime/pythonw.exe app/main.py"}), encoding="utf-8")
    # The exact three records INSTALL_THIS_PC.ps1 writes before it registers
    # the StartupUpdate task (Initialize-ContainerStartupUpdate).
    control = managed / "update-control"
    control.mkdir()
    for name, value in (
            ("transition.json", {"schema": update.SCHEMA, "phase": "DEFERRED", "failed_shas": []}),
            ("policy.json", {"schema": "container-audit-startup-update-policy-v1", "operator_sid": sid}),
            ("active.json", {"schema": update.SCHEMA, "sha": commit, "transition_id": "CANONICAL_INSTALL"})):
        (control / name).write_text(json.dumps(value), encoding="utf-8")
    return managed, fixed, sid


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("missing_task", "other_task", "owned_task"))
def test_records_without_task_refuse_with_bounded_reason(tmp_path, engine, case):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required")
    managed, fixed, sid = _interrupted_install(tmp_path)
    task_xml = tmp_path / "task.xml"
    task_xml.write_text(update.logon_task_xml(app_root=fixed, operator_sid=sid), encoding="utf-8")
    driver = tmp_path / "driver.ps1"
    driver.write_text(DRIVER, encoding="utf-8-sig")
    before = {p.relative_to(managed).as_posix(): p.read_bytes() for p in managed.rglob("*") if p.is_file()}
    environment = dict(os.environ, CA_LIFECYCLE_LIBRARY=str(ROOT / "tools/bootstrap_integrity.ps1"),
                       CA_LIFECYCLE_ROOT=str(managed), CA_LIFECYCLE_CASE=case,
                       CA_LIFECYCLE_TASK_XML=str(task_xml), CA_LIFECYCLE_TASK_NAME=update.task_name(fixed, sid))
    result = run_powershell([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(driver)],
                            env=environment, timeout=60)
    assert result.returncode == 0, result.stderr
    actual = json.loads(result.stdout)
    if case == "owned_task":
        assert actual == {"ok": True, "state": "HEALTHY"}
    else:
        # Refusal and its fixed public message are unchanged; the first cause is
        # the same allowlisted code the Python classifier raises.
        assert actual["ok"] is False
        assert actual["error"] == update.LIFECYCLE_RECOVERY
        assert actual["causes"][0] == "lifecycle_task_absence_or_unknown"
    assert {p.relative_to(managed).as_posix(): p.read_bytes() for p in managed.rglob("*") if p.is_file()} == before

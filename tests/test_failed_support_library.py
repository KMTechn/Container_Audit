"""Exercise FAILED support classification in both shipped PowerShell engines."""
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from tests.powershell_contracts import run_powershell

REPO = Path(__file__).resolve().parents[1]
DRIVER = r'''
param([string]$Metadata)
$ErrorActionPreference='Stop'
$m=Get-Content -LiteralPath $Metadata -Raw|ConvertFrom-Json
# Bind the child machine fence namespace to this test fixture.
$env:PROGRAMDATA=Join-Path (Split-Path -Parent $m.root) 'machine'
. (Join-Path $m.repo 'tools/bootstrap_integrity.ps1')
$script:stockCalls=0;$script:taskCalls=0;$script:censusCalls=0;$script:sharedCalls=0
function Get-BootstrapReplacementTreeIdentity([string]$Root,[string]$DeclaredCodeRoot) {
    $script:stockCalls++
    if($m.case -ceq 'code' -and $Root -like '*\versions\*'){throw 'changed inventory'}
    return [pscustomobject]@{owner_sid=('S-1-'+'5-32-544');access_rules_protected=$true}
}
function Export-ScheduledTask { $script:taskCalls++;Get-Content -LiteralPath (Join-Path $m.root 'task.xml') -Raw }
function Get-CimInstance {
    $script:censusCalls++
    $command=if($m.case -ceq 'writer'){(Join-Path $m.root 'versions')+'\writer.py'}else{'unrelated process'}
    return [pscustomobject]@{ProcessId=($PID+1);ExecutablePath='';CommandLine=$command}
}
function Get-BootstrapSharedPortableLeaf { $script:sharedCalls++;Join-Path $m.repo 'kmtech_shared/powershell/data_generation.ps1' }
$fencePath=Join-Path $m.local 'KMTech/DirectSync/container_audit/control/writer-session/active.json'
$preparedPath=Join-Path $m.root 'self-prepared.json'
$self=$null
if($m.case -in @('self','self_hash','self_thread','other_fence')) {
    $self=[pscustomobject]@{
        process_id=$PID;thread_id=[Threading.Thread]::CurrentThread.ManagedThreadId
        fence_path=$fencePath;fence_sha256=(Get-FileSha256 $fencePath)
        prepared_path=$preparedPath;prepared_sha256=(Get-FileSha256 $preparedPath)
        session_id=('a'*32);attempt_id=('b'*32);replacement_transaction_id=('c'*32)
    }
    if($m.case -ceq 'self_hash'){$self.fence_sha256='0'*64}
    if($m.case -ceq 'self_thread'){$self.thread_id++}
}
function Read-ContainerWriterFence([string]$ControlRoot,[switch]$AllowAbsent) {
    $path=Join-Path $ControlRoot 'active.json'
    if(Test-Path -LiteralPath $path) {
        return [pscustomobject]@{
            prepared_receipt_path=$preparedPath;prepared_receipt_sha256=(Get-FileSha256 $preparedPath)
            session_id=('a'*32);attempt_id=('b'*32);replacement_transaction_id=('c'*32)
        }
    }
    return $null
}
$ok=$false;$types=@();$locations=@()
try {
    if($m.case -in @('self','self_hash','self_thread','other_fence')) {
        $result=Get-BootstrapSupportedLifecycleContext $m.root 'install' -SelfIdentity $self
    } elseif($m.case -ceq 'ordinary') {
        $result=Get-BootstrapSupportedLifecycleContext $m.root 'install'
    } else {
        $result=Get-BootstrapSupportedLifecycleContext $m.root 'install' -FailedSupportPreflight
    }
    $ok=($result.status -ceq 'PASS')
} catch {
    $errorValue=$_.Exception
    while($null -ne $errorValue){$types+=,$errorValue.GetType().Name;$errorValue=$errorValue.InnerException}
    foreach($frame in ($_.ScriptStackTrace -split "`n")){
        if($frame -match '^at ([A-Za-z0-9_<>-]+), .*: line ([0-9]+)$'){$locations+=,@{function=$Matches[1];line=[int]$Matches[2]}}
    }
}
@{allowed=$ok;types=$types;locations=$locations;stock=$script:stockCalls;task=$script:taskCalls;census=$script:censusCalls;shared=$script:sharedCalls}|ConvertTo-Json -Compress -Depth 4
'''


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh"])
@pytest.mark.parametrize("case", ["allow", "code", "writer", "generation", "fence", "prepared",
                                  "self", "self_hash", "self_thread", "other_fence", "ordinary"])
def test_failed_library_checks_proofs_and_same_thread_identity(tmp_path, monkeypatch, engine, case):
    if not shutil.which(engine):
        pytest.skip("engine unavailable")
    import auto_update as update
    from kmtech_shared import data_generation as generation

    root = tmp_path / "managed"
    local = tmp_path / "local"
    machine = tmp_path / "machine"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("PROGRAMDATA", str(machine))
    monkeypatch.delenv("CONTAINER_AUDIT_DATA_ROOT", raising=False)
    active, old = "b" * 40, "a" * 40
    sid = "-".join(map(str, ("S", 1, 5, 21, 101, 102, 103, 1001)))
    for bundle, sha in ((root / "current", old), (root / "versions" / active, active)):
        (bundle / "runtime").mkdir(parents=True)
        (bundle / "app").mkdir()
        (bundle / "runtime/pythonw.exe").write_bytes(b"isolated runtime placeholder")
        (bundle / "app/main.py").write_bytes(b"# isolated entrypoint")
        (bundle / "app/update-manifest-key-config.json").write_bytes(b"isolated trust configuration")
        (bundle / "portable-manifest.json").write_text(json.dumps(dict(
            schema="container-audit-portable-tree-v1", source_commit=sha,
            entrypoint="runtime/pythonw.exe app/main.py", version="v2.0.112",
        )), encoding="utf-8")
    control = root / "update-control"
    control.mkdir()
    staging = root / "staging"
    staging.mkdir()
    policy = dict(schema="container-audit-startup-update-policy-v1", operator_sid=sid,
                  operator_local_app_data=str(local), feed_url="https://updates.invalid/", staging_root=str(staging))
    state = dict(schema=update.SCHEMA, phase="FAILED", reason="readiness failure", failed_shas=[])
    for name, value in (("policy", policy), ("active", dict(schema=update.SCHEMA, sha=active)), ("transition", state)):
        (control / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
    marker = local / "KMTech/ContainerAudit/data-generation.json"
    marker.parent.mkdir(parents=True)
    version = "v99.0.0" if case == "generation" else "v2.0.112"
    generation.record_generation(marker, version, app_id="container_audit", subject_sid=sid, build_id=active)
    if case == "prepared":
        (staging / "prepared.json").write_text(json.dumps(dict(source_commit="c" * 40)), encoding="utf-8")
    if case in {"self", "self_hash", "self_thread", "other_fence", "fence"}:
        fence = local / "KMTech/DirectSync/container_audit/control/writer-session/active.json"
        fence.parent.mkdir(parents=True)
        fence.write_bytes(b"isolated fence snapshot")
        (root / "self-prepared.json").write_bytes(b"isolated receipt snapshot")
    if case == "other_fence":
        other = machine / "KMTech/ContainerAudit/machine-install/control/writer-session/active.json"
        other.parent.mkdir(parents=True)
        other.write_bytes(b"other execution fence")
    (root / "task.xml").write_text(update.logon_task_xml(app_root=root / "current", operator_sid=sid), encoding="utf-8")
    metadata = tmp_path / "case.json"
    metadata.write_text(json.dumps(dict(repo=str(REPO), root=str(root), local=str(local), case=case)), encoding="utf-8")
    driver = tmp_path / "case.ps1"
    driver.write_text(DRIVER, encoding="utf-8-sig")
    before = {path: path.read_bytes() for path in control.iterdir()}
    result = run_powershell([engine, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver), str(metadata)])
    assert result.returncode == 0
    decision = json.loads(result.stdout)
    (tmp_path / "library-diagnostic.json").write_text(json.dumps(decision), encoding="utf-8")
    assert decision["allowed"] == (case in {"allow", "self"})
    assert all(path.read_bytes() == raw for path, raw in before.items())

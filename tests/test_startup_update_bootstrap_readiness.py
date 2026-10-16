"""Exercise the shipped Observe classifier before the real READY consumers."""
import contextlib
import json
from pathlib import Path
import subprocess
import time
import uuid

import pytest

import auto_update as updates
from test_auto_update import OLD, NEW, NOW, LATER, trial, ready
from test_auto_update_recovery_relay import recovery  # noqa: F401


@pytest.fixture
def observe(tmp_path):
    root = tmp_path / "managed" / "current"
    root.mkdir(parents=True)
    owner = uuid.uuid4().hex
    source = Path("tools/apply_prepared_update.ps1").read_text(encoding="utf-8-sig")
    function = "function Get-StartupUpdateProcesses" + source.split(
        "function Get-StartupUpdateProcesses", 1)[1].split("\nfunction ", 1)[0]
    script = tmp_path / "observe.ps1"
    script.write_text(r'''
param([string]$Root,[string]$InputFile,[string]$OutputFile)
$ErrorActionPreference='Stop'
trap {
    @{error_type=$_.Exception.GetType().Name;line=$_.InvocationInfo.ScriptLineNumber} | ConvertTo-Json -Compress | Set-Content -LiteralPath ($OutputFile + '.error.json') -Encoding UTF8
    exit 1
}
Add-Type 'public static class KMTechStartupUpdateToken { public static bool Ordinary(uint pid) { return pid != 3003; } }'
$inputRows=Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json
$script:ownerCalls=@()
function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) return $inputRows }
function Invoke-CimMethod {
    param($InputObject,$MethodName,$ErrorAction)
    $script:ownerCalls += [int]$InputObject.ProcessId
    if ($InputObject.ProcessId -eq 3004) { throw 'unobservable owner' }
    return [pscustomobject]@{ReturnValue=0;Sid=$InputObject.Owner}
}
function Assert-BootstrapNoReparsePoint { param($Path,$Label) }
''' + function + r'''
$rows=Get-StartupUpdateProcesses $Root
@{rows=@($rows);owner_calls=@($script:ownerCalls)} | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath $OutputFile -Encoding UTF8
''', encoding="utf-8-sig")

    def row(pid, role, *, sha=OLD, bootstrap=False, variant=None, sid=None, born=NOW):
        bundle = root if bootstrap else root.parent / "versions" / sha
        if variant == "outside":
            bundle = tmp_path / "outside"
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "portable-manifest.json").write_text(json.dumps({
            "schema": "container-audit-portable-tree-v1", "source_commit": sha}), encoding="utf-8")
        image = bundle / "runtime" / "pythonw.exe"
        entry = bundle / "app" / ("auto_update.py" if bootstrap else "main.py")
        if variant == "runtime":
            image = bundle / "other-runtime" / "pythonw.exe"
        if variant == "entry":
            entry = bundle / "app" / "other_update.py"
        command = f'"{image}" -I -B "{entry}"'
        if bootstrap:
            command += " --bootstrap"
        if role == "relay":
            command += " --role relay -- --container-audit-user-relay" if bootstrap else " --container-audit-user-relay"
        return dict(ProcessId=pid, Name="pythonw.exe", ExecutablePath=str(image),
                    CommandLine=command, CreationDate=born, Owner=sid or owner)

    def run(processes):
        input_file, output_file = tmp_path / "processes.json", tmp_path / "observed.json"
        input_file.write_text(json.dumps(processes), encoding="utf-8")
        result = subprocess.run([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass", "-File", str(script), "-Root", str(root),
            "-InputFile", str(input_file), "-OutputFile", str(output_file)],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0
        return json.loads(output_file.read_text(encoding="utf-8-sig"))

    return type("Observation", (), {"row": staticmethod(row), "run": staticmethod(run), "owner": owner})()


@pytest.mark.parametrize("phase", ["APPLIED_PENDING_READY", "ROLLBACK_PENDING_READY"])
@pytest.mark.parametrize("real_relays", [0, 1, 2])
def test_bootstrap_does_not_supply_or_duplicate_ready_relay(observe, tmp_path, monkeypatch, phase, real_relays):
    state = trial()
    state.update(phase=phase, rollback_at=NOW)
    sha = NEW if phase == "APPLIED_PENDING_READY" else OLD
    receipt = {**ready(state), "sha": sha}
    processes = [observe.row(state["trial_pid"], "gui", sha=sha)]
    processes += [observe.row(501 + i, "relay", sha=sha) for i in range(real_relays)]
    processes += [observe.row(601, "relay", bootstrap=True, born=LATER)]
    result = observe.run(processes)
    rows = result["rows"]
    monkeypatch.setattr(updates, "now_utc", lambda: LATER)
    policy = {"operator_sid": observe.owner}
    final, confirmed, exited = updates.observe_trial_ready(
        tmp_path, policy, state, rows, None, receipt, deadline=time.monotonic() + 60)
    assert confirmed is (real_relays == 1)
    assert not exited
    expected = ("CONFIRMED" if phase == "APPLIED_PENDING_READY" else "ROLLED_BACK") if confirmed else phase
    assert final["phase"] == expected
    assert [row["pid"] for row in rows if row["role"] == "gui"] == [state["trial_pid"]]
    assert len(updates.writer_processes(rows, own_pid=-1)) == real_relays + 1


@pytest.mark.parametrize("restart_elapsed", [0, 30])
@pytest.mark.parametrize("real_relays", [0, 1, 2])
def test_rollback_window_reuses_observed_rows_after_restart(observe, tmp_path, monkeypatch, restart_elapsed, real_relays):
    state = {**trial(), "phase": "ROLLBACK_PENDING_READY", "rollback_at": NOW}
    processes = [observe.row(state["trial_pid"], "gui")]
    processes += [observe.row(501 + i, "relay") for i in range(real_relays)]
    processes += [observe.row(601, "relay", bootstrap=True, born=LATER)]
    rows = observe.run(processes)["rows"]
    control, stage = tmp_path / "control", tmp_path / "stage"
    control.mkdir(); stage.mkdir()
    (control / "transition.json").write_text(json.dumps(state), encoding="utf-8")
    (control / "active.json").write_text(json.dumps({"sha": OLD}), encoding="utf-8")
    (stage / "ready.json").write_text(json.dumps({**ready(state), "sha": OLD}), encoding="utf-8")
    clock = [float(restart_elapsed)]
    monkeypatch.setattr(updates, "update_lock", lambda *_: contextlib.nullcontext())
    monkeypatch.setattr(updates, "process_snapshot", lambda *_: rows)
    monkeypatch.setattr(updates, "now_utc", lambda: LATER)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    rc = updates.wait_for_rollback_ready(control, {"staging_root": str(stage), "operator_sid": observe.owner})
    final = updates.read_json(control / "transition.json")
    assert rc == (0 if real_relays == 1 else 20)
    assert final["phase"] == ("ROLLED_BACK" if real_relays == 1 else "FAILED")
    assert final["rollback_at"] == NOW


def test_fixed_gui_and_relay_bootstraps_are_omitted_before_owner_query(observe):
    actual = [observe.row(500, "gui"), observe.row(501, "relay")]
    bootstraps = [observe.row(601, "relay", bootstrap=True), observe.row(602, "gui", bootstrap=True)]
    before = observe.run(actual)
    after = observe.run(actual + bootstraps)
    assert after == before
    assert len(updates.writer_processes(after["rows"], own_pid=-1)) == 2


@pytest.mark.parametrize("variant", ["outside", "runtime", "entry"])
def test_similar_commands_keep_existing_classification(observe, variant):
    result = observe.run([observe.row(601, "relay", bootstrap=True, variant=variant)])
    assert len(result["rows"]) == 1
    assert result["rows"][0]["role"] == "relay"
    assert result["rows"][0]["bootstrap"] is False
    assert result["owner_calls"] == [601]


def test_unobservable_foreign_and_elevated_rows_are_preserved(observe):
    processes = [observe.row(3003, "relay"), observe.row(3004, "relay"),
                 observe.row(3005, "relay", sid=uuid.uuid4().hex)]
    rows = observe.run(processes)["rows"]
    assert len(rows) == 3
    assert rows[0]["ordinary_user"] is False
    assert rows[1]["observable"] is False
    assert rows[2]["sid"] != observe.owner


def test_concurrent_requests_ignore_waiting_bootstraps_and_reuse_real_relay(recovery, observe, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    r = recovery
    def snapshot(*_):
        processes = [observe.row(row["pid"], row["role"], sha=row["sha"],
                                 sid=row["sid"], born=row["created_at"]) for row in r.rows]
        processes += [observe.row(601, "relay", bootstrap=True), observe.row(602, "relay", bootstrap=True)]
        return observe.run(processes)["rows"]
    monkeypatch.setattr(updates, "process_snapshot", snapshot)
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(lambda _: r.invoke(), range(2))) == [0, 0]
    assert len(r.launches) == 1
    r.unchanged()

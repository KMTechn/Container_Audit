from pathlib import Path
import json
import subprocess

import pytest

import user_relay


@pytest.mark.parametrize("case,expected", [
    ("foreign", 0), ("exited", 0), ("late-exit", 0), ("retry", 1),
    ("possible", 1), ("unknown-owner", 1),
])
def test_update_observer_rechecks_unreadable_python(tmp_path, case, expected):
    source = Path("tools/apply_prepared_update.ps1").read_text(encoding="utf-8-sig")
    function = source.split("function Get-StartupUpdateProcesses", 1)[1].split("\nfunction ", 1)[0]
    shared = Path("tools/bootstrap_integrity.ps1").read_text(encoding="utf-8-sig")
    marker = "function Test-BootstrapProcessRootPrefix("
    prefix_helper = marker + shared.split(marker, 1)[1].split("\nfunction ", 1)[0] if marker in shared else ""
    function = prefix_helper + "\n" + function
    function = "function Get-StartupUpdateProcesses" + function
    bundle = tmp_path / "current"
    bundle.mkdir()
    (bundle / "portable-manifest.json").write_text(json.dumps({"source_commit": "a" * 40}))
    script = tmp_path / "observe.ps1"
    script.write_text("""
param([string]$Root,[string]$Case)
$ErrorActionPreference='Stop'
Add-Type 'public static class KMTechStartupUpdateToken { public static bool Ordinary(uint pid) { return true; } }'
$authority=@{policy=@{operator_sid='fixture-owner'}}
$script:reads=0
function Get-CimInstance {
 param($ClassName,$Filter,$ErrorAction)
 $script:reads++
 if($Filter -and $Case -eq 'exited'){return}
 if($Filter -and $Case -eq 'late-exit' -and $script:reads -ge 3){return}
 $image=''
 if($Filter -and $Case -eq 'retry'){$image=Join-Path $Root 'runtime/pythonw.exe'}
 [pscustomobject]@{ExecutablePath=$image;Name='pythonw.exe';ProcessId=41;CommandLine='';
  CreationDate=[datetime]'2026-10-13T00:00:00Z';SessionId=1;ParentProcessId=0}
}
function Invoke-CimMethod {
 param($InputObject,$MethodName,$ErrorAction)
 if($Case -eq 'unknown-owner'){throw 'owner observation unavailable'}
 @{ReturnValue=0;Sid=$(if($Case -eq 'foreign'){'fixture-other'}else{'fixture-owner'})}
}
function Assert-BootstrapNoReparsePoint {}
""" + function + "\n$rows=Get-StartupUpdateProcesses $Root\n" +
        "ConvertTo-Json -InputObject @{count=@($rows).Count;reads=$script:reads;" +
        "observable=(@($rows | Where-Object {$_.observable -eq $true}).Count)} -Compress\n",
        encoding="utf-8-sig")
    result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", str(script),
        "-Root", str(bundle), "-Case", case], capture_output=True, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0
    observed = json.loads(result.stdout)
    assert observed["count"] == expected
    assert observed["reads"] >= 2
    assert observed["observable"] == (1 if case == "retry" else 0)


@pytest.mark.parametrize("exited", [False, True])
def test_stop_native_query_rechecks_candidates_without_host_observation(tmp_path, monkeypatch, exited):
    run = subprocess.run
    def fake_query(arguments, **kwargs):
        import writer_session_fence
        assert getattr(writer_session_fence._WRITER_LOCAL, "depth", 0) == 0
        script = tmp_path / "native-query.ps1"
        script.write_text("""
$script:reads=0
function Get-CimInstance {
 param($ClassName,$Filter,$OperationTimeoutSec,$ErrorAction)
 $script:reads++
 if($Filter){
  if($exited){return}
  return [pscustomobject]@{Name='pythonw.exe';ProcessId=41;ExecutablePath='E:\\installed\\runtime\\pythonw.exe';
   CommandLine='';ParentProcessId=0;SessionId=1;CreationDate=[datetime]'2026-10-13T00:00:00Z'}
 }
 [pscustomobject]@{Name='pythonw.exe';ProcessId=41;ExecutablePath='';CommandLine='';
  ParentProcessId=0;SessionId=1;CreationDate=[datetime]'2026-10-13T00:00:00Z'}
 [pscustomobject]@{Name='other.exe';ProcessId=44;ExecutablePath='E:\\other.exe';CommandLine='';
  ParentProcessId=0;SessionId=1;CreationDate=[datetime]'2026-10-13T00:00:00Z'}
}
""".replace("$exited", "$true" if exited else "$false") + arguments[-1], encoding="utf-8-sig")
        return run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle",
                    "Hidden", "-ExecutionPolicy", "Bypass", "-File", str(script)], **kwargs)
    monkeypatch.setattr(user_relay.subprocess, "run", fake_query)
    rows = user_relay.native_app_process_snapshot()
    assert [r["pid"] for r in rows] == ([] if exited else [41])
    if not exited:
        assert rows[0]["image"].endswith("runtime\\pythonw.exe")

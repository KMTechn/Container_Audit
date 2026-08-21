import ctypes
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_FENCE = ROOT / "tools" / "enter_release_powershell_module_fence.ps1"
PWSH = shutil.which("pwsh")


def _known_folder(csidl):
    buffer = ctypes.create_unicode_buffer(32768)
    result = ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buffer)
    if result != 0:
        raise OSError(result, f"SHGetFolderPathW failed for CSIDL {csidl}")
    return Path(buffer.value)


def _module_contract(tmp_path):
    pwsh_path = Path(PWSH)
    current_user_modules = _known_folder(5) / "PowerShell" / "Modules"
    all_users_modules = _known_folder(38) / "PowerShell" / "Modules"
    windows_modules = (
        Path(r"C:\Windows")
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "Modules"
    )
    sealed_module_path = os.pathsep.join(
        (str(pwsh_path.parent / "Modules"), str(windows_modules))
    )
    effective_module_path = os.pathsep.join(
        (
            str(current_user_modules),
            str(all_users_modules),
            sealed_module_path,
        )
    )
    analysis_cache_path = tmp_path / "module-analysis-cache" / "ModuleAnalysisCache"
    temp_path = tmp_path / "temp"
    tmp_path_value = tmp_path / "tmp"
    analysis_cache_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path.mkdir(exist_ok=True)
    tmp_path_value.mkdir(exist_ok=True)
    return {
        "sealed": sealed_module_path,
        "effective": effective_module_path,
        "current_user": str(current_user_modules),
        "all_users": str(all_users_modules),
        "analysis_cache": str(analysis_cache_path),
        "temp": str(temp_path),
        "tmp": str(tmp_path_value),
    }


def _run_child_fence(tmp_path, *, environment_updates=None):
    contract = _module_contract(tmp_path)
    driver_path = tmp_path / "Invoke-TestModuleFence.ps1"
    child_stdout_path = tmp_path / "child.stdout.txt"
    child_stderr_path = tmp_path / "child.stderr.txt"
    environment = os.environ.copy()
    environment.update(
        {
            "PSModulePath": contract["sealed"],
            "PSModuleAnalysisCachePath": contract["analysis_cache"],
            "TEMP": contract["temp"],
            "TMP": contract["tmp"],
            "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH": contract["sealed"],
            "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH_SHA256": hashlib.sha256(
                contract["sealed"].encode("utf-8")
            ).hexdigest(),
            "KMTECH_TEST_MODULE_FENCE": str(MODULE_FENCE),
            "KMTECH_TEST_CURRENT_USER_MODULE_PATH": contract["current_user"],
            "KMTECH_TEST_ALL_USERS_MODULE_PATH": contract["all_users"],
            "KMTECH_TEST_EXPECTED_ANALYSIS_CACHE_PATH": contract["analysis_cache"],
            "KMTECH_TEST_CHILD_PRELAUNCH_MODULE_PATH": contract["sealed"],
            "KMTECH_TEST_PWSH": PWSH,
            "KMTECH_TEST_CHILD_DRIVER": str(driver_path),
            "KMTECH_TEST_CHILD_STDOUT": str(child_stdout_path),
            "KMTECH_TEST_CHILD_STDERR": str(child_stderr_path),
        }
    )
    environment.pop("PSDisableModuleAnalysisCacheCleanup", None)
    if environment_updates:
        environment.update(environment_updates)

    driver = r"""
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$beforeModulePath = [string]$env:PSModulePath
. $env:KMTECH_TEST_MODULE_FENCE
try {
    Enter-ReleasePowerShellModuleFence `
        -ExpectedCurrentUserModulePath $env:KMTECH_TEST_CURRENT_USER_MODULE_PATH `
        -ExpectedAllUsersModulePath $env:KMTECH_TEST_ALL_USERS_MODULE_PATH `
        -ExpectedAnalysisCachePath $env:KMTECH_TEST_EXPECTED_ANALYSIS_CACHE_PATH
    [ordered]@{
        status = "PASS"
        before_module_path = $beforeModulePath
        after_module_path = [string]$env:PSModulePath
        analysis_cache_path = [string]$env:PSModuleAnalysisCachePath
        prelaunch_token_present = (
            [Environment]::GetEnvironmentVariable(
                "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH",
                [EnvironmentVariableTarget]::Process
            ) -ne $null
        )
        prelaunch_digest_token_present = (
            [Environment]::GetEnvironmentVariable(
                "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH_SHA256",
                [EnvironmentVariableTarget]::Process
            ) -ne $null
        )
    } | ConvertTo-Json -Compress
}
catch {
    [ordered]@{
        status = "REJECTED"
        reason = $_.Exception.Message
        before_module_path = $beforeModulePath
        after_module_path = [string]$env:PSModulePath
        analysis_cache_path = [string]$env:PSModuleAnalysisCachePath
        prelaunch_token_present = (
            [Environment]::GetEnvironmentVariable(
                "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH",
                [EnvironmentVariableTarget]::Process
            ) -ne $null
        )
        prelaunch_digest_token_present = (
            [Environment]::GetEnvironmentVariable(
                "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH_SHA256",
                [EnvironmentVariableTarget]::Process
            ) -ne $null
        )
    } | ConvertTo-Json -Compress
    exit 41
}
"""
    driver_path.write_text(driver, encoding="utf-8")
    parent_command = r"""
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$env:PSModulePath = $env:KMTECH_TEST_CHILD_PRELAUNCH_MODULE_PATH
$process = Start-Process `
    -FilePath $env:KMTECH_TEST_PWSH `
    -WindowStyle Hidden `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $env:KMTECH_TEST_CHILD_STDOUT `
    -RedirectStandardError $env:KMTECH_TEST_CHILD_STDERR `
    -ArgumentList @(
        "-NoProfile",
        "-NonInteractive",
        "-File",
        $env:KMTECH_TEST_CHILD_DRIVER
    )
exit $process.ExitCode
"""
    parent = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", parent_command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    child_stdout = child_stdout_path.read_text(encoding="utf-8-sig")
    child_stderr = child_stderr_path.read_text(encoding="utf-8-sig")
    completed = subprocess.CompletedProcess(
        args=parent.args,
        returncode=parent.returncode,
        stdout=child_stdout,
        stderr=parent.stderr + child_stderr,
    )
    return contract, completed, json.loads(child_stdout)


def test_release_module_fence_contract_has_no_module_resolution_before_fencing():
    script = MODULE_FENCE.read_text(encoding="utf-8")

    assert "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH" in script
    assert "KMTECH_RELEASE_PRELAUNCH_MODULE_PATH_SHA256" in script
    assert "GetFolderPath([Environment+SpecialFolder]::MyDocuments)" in script
    assert "GetFolderPath([Environment+SpecialFolder]::ProgramFiles)" in script
    assert 'GetFullPath("E:\\KMTech")' in script
    assert "Import-Module" not in script
    assert "Get-Module" not in script
    assert "Get-Command" not in script


@pytest.mark.skipif(os.name != "nt" or PWSH is None, reason="requires PowerShell 7 on Windows")
def test_new_pwsh_child_accepts_only_expected_startup_expansion_then_seals(tmp_path):
    contract, completed, result = _run_child_fence(tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert result == {
        "status": "PASS",
        "before_module_path": contract["effective"],
        "after_module_path": contract["sealed"],
        "analysis_cache_path": contract["analysis_cache"],
        "prelaunch_token_present": False,
        "prelaunch_digest_token_present": False,
    }


@pytest.mark.skipif(os.name != "nt" or PWSH is None, reason="requires PowerShell 7 on Windows")
@pytest.mark.parametrize("position", ("before", "after"))
def test_new_pwsh_child_rejects_an_extra_hostile_c_module_path(tmp_path, position):
    hostile_path = Path(r"C:\hostile-v2075-module-path")
    assert not hostile_path.exists()
    contract = _module_contract(tmp_path)
    hostile_prelaunch = os.pathsep.join(
        (str(hostile_path), contract["sealed"])
        if position == "before"
        else (contract["sealed"], str(hostile_path))
    )

    _, completed, result = _run_child_fence(
        tmp_path,
        environment_updates={
            "KMTECH_TEST_CHILD_PRELAUNCH_MODULE_PATH": hostile_prelaunch,
        },
    )

    assert completed.returncode == 41
    assert result["status"] == "REJECTED"
    assert "exact PowerShell startup closure" in result["reason"]
    assert result["after_module_path"] == result["before_module_path"]
    assert result["prelaunch_token_present"] is True
    assert result["prelaunch_digest_token_present"] is True
    assert not hostile_path.exists()


@pytest.mark.skipif(os.name != "nt" or PWSH is None, reason="requires PowerShell 7 on Windows")
@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("KMTECH_RELEASE_PRELAUNCH_MODULE_PATH", r"C:\hostile-v2075"),
        ("KMTECH_RELEASE_PRELAUNCH_MODULE_PATH_SHA256", "0" * 64),
    ),
)
def test_new_pwsh_child_rejects_a_changed_prelaunch_token(tmp_path, name, value):
    contract, completed, result = _run_child_fence(
        tmp_path,
        environment_updates={name: value},
    )

    assert completed.returncode == 41
    assert result["status"] == "REJECTED"
    assert "exact hash-bound prelaunch module-path token" in result["reason"]
    assert result["before_module_path"] == contract["effective"]
    assert result["after_module_path"] == contract["effective"]


@pytest.mark.skipif(os.name != "nt" or PWSH is None, reason="requires PowerShell 7 on Windows")
def test_release_module_fence_rejects_a_c_drive_analysis_cache_contract(tmp_path):
    hostile_cache = Path(r"C:\hostile-v2075-cache\ModuleAnalysisCache")
    assert not hostile_cache.parent.exists()

    _, completed, result = _run_child_fence(
        tmp_path,
        environment_updates={
            "KMTECH_TEST_EXPECTED_ANALYSIS_CACHE_PATH": str(hostile_cache),
        },
    )

    assert completed.returncode == 41
    assert result["status"] == "REJECTED"
    assert "exact E:\\KMTech path" in result["reason"]
    assert result["after_module_path"] == result["before_module_path"]
    assert not hostile_cache.parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="release PowerShell scripts are Windows-only")
def test_release_module_fence_powershell_parses(tmp_path):
    escaped = str(MODULE_FENCE).replace("'", "''")
    command = (
        "$tokens=$null;$errors=$null;"
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{escaped}',[ref]$tokens,[ref]$errors);"
        "if($errors.Count){$errors|ForEach-Object{$_.Message}|Write-Error;exit 1}"
    )
    environment = os.environ.copy()
    environment["PSModuleAnalysisCachePath"] = str(
        tmp_path / "parse-module-analysis-cache" / "ModuleAnalysisCache"
    )
    environment["TEMP"] = str(tmp_path)
    environment["TMP"] = str(tmp_path)
    environment.pop("PSDisableModuleAnalysisCacheCleanup", None)
    for executable in ("powershell", "pwsh"):
        if shutil.which(executable) is None:
            continue
        subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", command],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )

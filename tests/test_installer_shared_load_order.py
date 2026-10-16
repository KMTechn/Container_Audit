"""Fresh installer admission must work before pinned shared code is imported."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from tests._installer_host_isolation import host_program_data_guard
from tests.test_zero_touch_installer import _portable_release_fixture


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"


def _audit_load_order(tmp_path, engine, source, library_root, mutation=""):
    audit_path = tmp_path / ("pre-shared-load-" + (mutation or "actual") + ".json")
    environment = os.environ.copy()
    environment.update({"KMTECH_FACTORY_INSTALL_TEST_MODE": "1", "PROGRAMDATA": str(tmp_path / "program-data"),
                        "TEMP": str(tmp_path), "TMP": str(tmp_path)})
    result = subprocess.run(
        [shutil.which(engine), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(ROOT / "tests/installer_load_order_audit.ps1"), "-Source", str(source),
         "-LibraryRoot", str(library_root), "-AuditPath", str(audit_path), "-Mutation", mutation],
        cwd=tmp_path, env=environment, capture_output=True, encoding="utf-8", errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert audit_path.exists(), "Static audit did not complete; isolated output retained"
    return result, json.loads(audit_path.read_text(encoding="utf-8-sig"))


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_pre_shared_load_call_graph_has_no_shared_only_dependency(tmp_path, engine, host_program_data_guard):
    if not shutil.which(engine):
        pytest.skip(f"{engine} is required")
    host_program_data_guard.assert_unchanged()
    result, audit = _audit_load_order(tmp_path, engine, INSTALLER, ROOT)
    assert result.returncode == 0, "pre-import call graph has an unavailable dependency; audit retained"
    assert {row["scenario"] for row in audit["frontiers"]} == {
        "no-arguments", "plan-only", "worker-inventory", "worker-evidence", "worker-evidence-plan-only",
        "machine-recovery", "restore", "retired-removal", "rollback-resume"}
    assert all(row["dependencies"] == [] for row in audit["frontiers"])
    assert {row["leaf"] for row in audit["frontiers"]} >= {"portable", "data", "fence"}
    mutant, changed = _audit_load_order(tmp_path, engine, INSTALLER, ROOT, "fence")
    assert mutant.returncode == 1, "Audit failed to detect an injected early shared helper call"
    assert any(row["dependencies"] for row in changed["frontiers"])
    early_data, changed = _audit_load_order(tmp_path, engine, INSTALLER, ROOT, "data")
    assert early_data.returncode == 1, "Audit missed a helper called before the function's own data import"
    assert any("Assert-KmtechDataIdentity" in row["dependencies"] for row in changed["frontiers"])


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
@pytest.mark.parametrize("caller", ["same-worker", "other-worker"])
def test_explicit_worker_evidence_plan_only_in_fresh_process(tmp_path, engine, caller, host_program_data_guard):
    executable = shutil.which(engine)
    if not executable:
        pytest.skip(f"{engine} is required")
    packet = _portable_release_fixture(tmp_path, directory="portable")
    profile = tmp_path / "worker-profile"
    program_data = tmp_path / "program-data"
    local = profile / "AppData/Local"
    inventory = tmp_path / "inventory.json"
    evidence = program_data / "KMTech/ContainerAudit/machine-install/install-audit/plan.json"
    install = tmp_path / "machine/current"
    worker_sid = "-".join(map(str, ("S", 1, 5, 21, 101, 202, 303, 1001)))
    caller_sid = worker_sid if caller == "same-worker" else worker_sid.rsplit("-", 1)[0] + "-1002"
    inventory.write_text(json.dumps({"status": "READY", "target_sid": worker_sid,
                                    "target_profile_root": str(profile)}), encoding="utf-8")

    # Keep the complete installer and pinned libraries. Replace only native
    # caller/ProfileList observations; worker admission and path guards are real.
    path = packet / INSTALLER.name
    product = path.read_text(encoding="utf-8-sig")
    start = product.index("function Get-CanonicalInstallationCallerSecurity {")
    finish = product.index("function Resolve-CanonicalWorkerSid", start)
    product = (product[:start] + "function Get-CanonicalInstallationCallerSecurity {\n"
               " return [pscustomobject]@{sid=$env:CA_PLAN_CALLER;session_id=1;elevated=$true}\n}\n\n"
               + product[finish:])
    start = product.index("function Get-CanonicalWorkerProfileRoot(")
    finish = product.index("function Get-CanonicalConsoleWorkerSecurity", start)
    product = (product[:start] + "function Get-CanonicalWorkerProfileRoot([string]$Sid) {\n"
               " return Full $env:CA_PLAN_PROFILE 'worker profile'\n}\n\n" + product[finish:])
    start = product.index("function Get-CanonicalWorkerPreparationPaths(")
    finish = product.index("function Initialize-CanonicalSameWorkerScope", start)
    preparation = product[start:finish]
    observation = "[Environment]::GetFolderPath([Environment+SpecialFolder]::$folder,[Environment+SpecialFolderOption]::DoNotVerify)"
    assert preparation.count(observation) == 1
    # Known-folder observations belong to the isolated profile too. Preserve
    # the real profile containment, path and reparse checks that consume them.
    preparation = preparation.replace(observation,
        "$(if($folder -eq 'Programs'){Join-Path $env:CA_PLAN_PROFILE 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs'}"
        "else{Join-Path $env:CA_PLAN_PROFILE 'Desktop'})")
    product = product[:start] + preparation + product[finish:]
    path.write_text(product, encoding="utf-8-sig")
    manifest_path = packet / "portable-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["installer_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    members = [p for p in packet.rglob("*") if p.is_file() and p != manifest_path]
    manifest["file_count_before_manifest"] = len(members)
    manifest["byte_count_before_manifest"] = sum(p.stat().st_size for p in members)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    temporary = tmp_path / "temp"
    temporary.mkdir()
    environment = os.environ.copy()
    environment.update({"KMTECH_FACTORY_INSTALL_TEST_MODE": "1", "PROGRAMDATA": str(program_data),
                        "PSModulePath": str(Path(executable).parent / "Modules"),
                        "LOCALAPPDATA": str(local), "APPDATA": str(profile / "AppData/Roaming"),
                        "TEMP": str(temporary), "TMP": str(temporary),
                        "CA_PLAN_PROFILE": str(profile), "CA_PLAN_CALLER": caller_sid})
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    directories_before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*") if p.is_dir()}
    host_program_data_guard.assert_unchanged()
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(path), "-SourceRoot", str(packet), "-InstallRoot", str(install),
         "-WorkerAccount", worker_sid, "-WorkerSurveyInventory", str(inventory), "-EvidencePath", str(evidence),
         "-PlanOnly", "-AllowNoncanonicalLayoutForTest", "-SkipSignatureValidationForTest"],
        cwd=tmp_path, env=environment, capture_output=True, encoding="utf-8", errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    host_program_data_guard.assert_unchanged()
    after = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    directories_after = {p.relative_to(tmp_path) for p in tmp_path.rglob("*") if p.is_dir()}
    summary = {"engine": engine, "exit_code": result.returncode,
               "files_unchanged": before == after, "directories_unchanged": directories_before == directories_after}
    (tmp_path / "fresh-plan-stdout.private.log").write_text(result.stdout, encoding="utf-8")
    (tmp_path / "fresh-plan-stderr.private.log").write_text(result.stderr, encoding="utf-8")
    (tmp_path / "fresh-plan-result.json").write_text(json.dumps(summary), encoding="utf-8")
    assert result.returncode == (4 if caller == 'same-worker' else 0)
    assert result.stderr == ""
    if caller == 'same-worker':
        assert "MACHINE_INSTALL_FAILED" in result.stdout
        assert "install_status=PLAN_ONLY" not in result.stdout
    else:
        assert "install_status=PLAN_ONLY" in result.stdout
    assert before == after, "PlanOnly changed the isolated files"
    assert directories_before == directories_after, "PlanOnly allocated a directory"
    assert not profile.exists() and not program_data.exists() and not install.exists()

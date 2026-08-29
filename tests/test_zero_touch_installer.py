import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "INSTALL_THIS_PC.ps1"
PORTABLE_INSTALLER = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"
INTEGRITY_HELPER = ROOT / "tools" / "bootstrap_integrity.ps1"


def _powershell() -> str:
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell is required")
    return executable


def _run_installer(source_root: Path, install_root: Path, *extra: str):
    environment = dict(os.environ)
    environment["KMTECH_FACTORY_INSTALL_TEST_MODE"] = "1"
    return subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(INSTALLER),
            "-SourceRoot",
            str(source_root),
            "-InstallRoot",
            str(install_root),
            "-AllowNoncanonicalLayoutForTest",
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )


def _release_fixture(root: Path) -> Path:
    release = root / "frozen-release"
    release.mkdir(parents=True)
    (release / "Container_Audit.exe").write_bytes(b"container-audit-frozen-exe")
    (release / "contract.lock.json").write_text(
        '{"lock_schema_version": 1}\n',
        encoding="utf-8",
    )
    (release / "runtime.dll").write_bytes(b"reachable-runtime")
    return release


def _portable_release_fixture(root: Path) -> Path:
    release = root / "portable release 한글"
    (release / "runtime").mkdir(parents=True)
    (release / "app").mkdir()
    (release / "runtime" / "python.exe").write_bytes(b"signed-python-test-double")
    pythonw = b"signed-pythonw-test-double"
    (release / "runtime" / "pythonw.exe").write_bytes(pythonw)
    (release / "app" / "main.py").write_text("# portable main\n", encoding="utf-8")
    launcher = b"@echo off\r\n"
    (release / "launch-container-audit.cmd").write_bytes(launcher)
    files = [path for path in release.rglob("*") if path.is_file()]
    manifest = {
        "schema": "container-audit-portable-tree-v1",
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "entrypoint": "runtime/pythonw.exe app/main.py",
        "launcher": "launch-container-audit.cmd",
        "runtime_pythonw_sha256": hashlib.sha256(pythonw).hexdigest(),
        "launcher_sha256": hashlib.sha256(launcher).hexdigest(),
        "allowed_unsigned_app_pe": [],
        "forbidden_dependency_paths": [],
        "file_count_before_manifest": len(files),
        "byte_count_before_manifest": sum(path.stat().st_size for path in files),
    }
    (release / "portable-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=True),
        encoding="utf-8",
    )
    return release


def _private_ca_pem() -> bytes:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Container Audit Test Private CA")]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def test_bootstrap_is_minimal_code_placement_contract():
    text = INSTALLER.read_text(encoding="utf-8")
    helper = INTEGRITY_HELPER.read_text(encoding="utf-8")

    assert len(text.splitlines()) <= 500
    assert '. (Join-Path $PSScriptRoot "tools\\bootstrap_integrity.ps1")' in text
    assert "container-audit-bootstrap-integrity-v1" in helper
    assert "Write-BootstrapIntegrityRecord" in text
    assert "identity_profile_created=false" in text
    assert "elevation_points=1:code_placement" in text
    assert "Set-HardenedCodeAcl" in text
    assert "Assert-HardenedCodeAcl" in text
    assert "'/setowner', '*S-1-5-32-544'" in text
    assert "'/reset', '/L'" in text
    assert "acl_readback_status=UNKNOWN" in text
    reuse_index = text.index("$bootstrapStatus = 'REUSED'")
    final_acl_index = text.index("Set-HardenedCodeAcl $installRootFull -Recursive")
    success_index = text.index('Write-Output "bootstrap_status=$bootstrapStatus"')
    assert reuse_index < final_acl_index < success_index
    assert "Register-ScheduledTask" not in text
    assert "New-ScheduledTask" not in text
    assert "Start-ScheduledTask" not in text
    assert "self-enroll" not in text
    assert "ProducerIdentityPath" not in text
    assert "ServerBaseUrl" not in text
    assert "EnableWindowsSandboxQualification" not in text
    assert "Remove-OwnedLegacyTask" in text
    assert "Test-CurrentUserRelayPersistencePresent" in text
    assert "--remove-current-user-setup" in text


def test_bootstrap_powershell_parses():
    for script in (INSTALLER, PORTABLE_INSTALLER, INTEGRITY_HELPER):
        escaped = str(script).replace("'", "''")
        completed = subprocess.run(
            [
                _powershell(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "$tokens=$null;$errors=$null;"
                    "[void][System.Management.Automation.Language.Parser]::ParseFile("
                    f"'{escaped}',[ref]$tokens,[ref]$errors);"
                    "if($errors.Count){$errors|ForEach-Object{$_.ToString()};exit 1}"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert completed.returncode == 0, completed.stderr or completed.stdout


def test_portable_autostart_persists_preimage_before_exact_swap_and_has_rollback():
    text = PORTABLE_INSTALLER.read_text(encoding="utf-8")

    preimage_index = text.index("Save $auditPath $audit")
    mutation_index = text.index("Product $install '--remove-current-user-setup'")
    assert preimage_index < mutation_index
    assert "Restore $before" in text
    assert "AUTOSTART_ROLLBACK_FAILED" in text
    assert "Product $install '--onboard-current-user'" in text
    assert "relay_autostart.command -cne $wanted" in text
    assert "StartRaw ([string]$item.CommandLine)" in text
    assert "cold_boot_status=UNPROVEN" in text


def test_portable_installer_fences_canonical_scheduled_writer_around_replacement():
    text = PORTABLE_INSTALLER.read_text(encoding="utf-8")
    audit_index = text.index("$audit = [ordered]@{")
    preimage_save_index = text.index("Save $auditPath $audit", audit_index)
    disable_index = text.index(
        "$writerDisabled = Disable-CanonicalWriter", preimage_save_index
    )
    stop_proof_index = text.index(
        "$writerStopped = Confirm-CanonicalWriterStopped", disable_index
    )
    placement_index = text.index("& $winps @bootstrap", stop_proof_index)
    product_pass_index = text.index("$audit.status='PRODUCT_PHASE_PASS'", placement_index)
    enable_index = text.index(
        "$writerEnabled = Enable-CanonicalWriter", product_pass_index
    )
    natural_trigger_index = text.index(
        "$writerRunning = Confirm-CanonicalWriterRunning", enable_index
    )
    final_pass_index = text.index("$audit.status='PASS'", natural_trigger_index)

    assert (
        preimage_save_index
        < disable_index
        < stop_proof_index
        < placement_index
        < product_pass_index
        < enable_index
        < natural_trigger_index
        < final_pass_index
    )
    assert "Disable-ScheduledTask" in text
    assert "Enable-ScheduledTask" in text
    assert "Start-ScheduledTask" not in text
    assert "CANONICAL_WRITER_STOP_PROOF_FAILED" in text
    assert "CANONICAL_WRITER_RESTORE_NEXT_TRIGGER_NOT_FUTURE" in text
    assert "CANONICAL_WRITER_NATURAL_TRIGGER_PROOF_FAILED" in text
    assert "CANONICAL_WRITER_RESTORE_FAILED" in text
    assert "log_size_mtime_sha256_unchanged=$true" in text
    assert "last_run_time_advanced=$true" in text
    assert "log_actual_write=$true" in text


def test_portable_installer_restore_binding_mismatch_is_explicit_without_mutation():
    environment = dict(os.environ)
    environment["KMTECH_TEST_INSTALLER_PATH"] = str(PORTABLE_INSTALLER)
    command = r"""
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:KMTECH_TEST_INSTALLER_PATH,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { exit 10 }
$functions = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-CanonicalWriterRestoreReadback'
}, $true))
if ($functions.Count -ne 1) { exit 11 }
Invoke-Expression $functions[0].Extent.Text
$before = [pscustomobject]@{ binding_sha256 = ('a' * 64) }
$after = [pscustomobject]@{
    present = $true
    classification = 'CANONICAL_QUIESCE_RESTORE'
    enabled = $true
    binding_sha256 = ('b' * 64)
}
try {
    Assert-CanonicalWriterRestoreReadback $before $after
    exit 12
}
catch {
    if ($_.Exception.Message -cne 'CANONICAL_WRITER_RESTORE_BINDING_MISMATCH') {
        exit 13
    }
}
exit 0
"""
    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_portable_plan_quotes_space_and_unicode_paths_without_registry_mutation(
    tmp_path,
):
    source = _portable_release_fixture(tmp_path)
    install = tmp_path / "설치 위치" / "Container Audit" / "current"
    environment = dict(os.environ)
    environment["KMTECH_FACTORY_INSTALL_TEST_MODE"] = "1"

    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(PORTABLE_INSTALLER),
            "-SourceRoot",
            str(source),
            "-InstallRoot",
            str(install),
            "-PlanOnly",
            "-AllowNoncanonicalLayoutForTest",
            "-SkipSignatureValidationForTest",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "install_status=PLAN_ONLY" in completed.stdout
    assert "registry_changed=false" in completed.stdout
    assert f'"{install / "runtime" / "pythonw.exe"}" -I -B' in completed.stdout
    assert (
        f'"{install / "app" / "main.py"}" --container-audit-user-relay'
        in completed.stdout
    )
    assert not install.exists()


def test_bootstrap_accepts_portable_tree_and_integrity_readback(tmp_path):
    source = _portable_release_fixture(tmp_path)
    install = tmp_path / "apps" / "portable current"

    completed = _run_installer(source, install)

    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "release_layout=PORTABLE_CPYTHON" in completed.stdout
    assert (install / "runtime" / "pythonw.exe").read_bytes() == (
        source / "runtime" / "pythonw.exe"
    ).read_bytes()
    environment = dict(os.environ)
    environment["KMTECH_TEST_BOOTSTRAP_HELPER"] = str(INTEGRITY_HELPER)
    environment["KMTECH_TEST_PACKAGE_ROOT"] = str(install)
    verified = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                ". $env:KMTECH_TEST_BOOTSTRAP_HELPER;"
                "Assert-BootstrapIntegrityRecord $env:KMTECH_TEST_PACKAGE_ROOT | Out-Null"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    assert verified.returncode == 0, verified.stderr or verified.stdout


def test_portable_build_integrity_record_survives_relocation_and_blocks_tamper(
    tmp_path,
):
    package = tmp_path / "build" / "Container_Audit"
    package.mkdir(parents=True)
    (package / "Container_Audit.exe").write_bytes(b"portable-main")
    (package / "runtime.dll").write_bytes(b"portable-runtime")
    environment = dict(os.environ)
    environment["KMTECH_TEST_BOOTSTRAP_HELPER"] = str(INTEGRITY_HELPER)
    environment["KMTECH_TEST_PACKAGE_ROOT"] = str(package)
    generate = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                ". $env:KMTECH_TEST_BOOTSTRAP_HELPER;"
                "Write-BootstrapIntegrityRecord -Root $env:KMTECH_TEST_PACKAGE_ROOT "
                "-CodeRootIdentity '.' | Out-Null;"
                "Assert-BootstrapIntegrityRecord $env:KMTECH_TEST_PACKAGE_ROOT | Out-Null"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    assert generate.returncode == 0, generate.stderr or generate.stdout
    record = json.loads((package / "bootstrap-integrity.json").read_text(encoding="utf-8"))
    assert record["code_root"] == "."
    assert {item["path"] for item in record["files"]} == {
        "Container_Audit.exe",
        "runtime.dll",
    }

    relocated = tmp_path / "Downloads" / "Container_Audit"
    relocated.parent.mkdir()
    shutil.move(str(package), str(relocated))
    environment["KMTECH_TEST_PACKAGE_ROOT"] = str(relocated)
    verify = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                ". $env:KMTECH_TEST_BOOTSTRAP_HELPER;"
                "Assert-BootstrapIntegrityRecord $env:KMTECH_TEST_PACKAGE_ROOT | Out-Null"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    assert verify.returncode == 0, verify.stderr or verify.stdout

    (relocated / "runtime.dll").write_bytes(b"tampered")
    blocked = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                ". $env:KMTECH_TEST_BOOTSTRAP_HELPER;"
                "Assert-BootstrapIntegrityRecord $env:KMTECH_TEST_PACKAGE_ROOT | Out-Null"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    assert blocked.returncode != 0
    assert "inventory differs" in (blocked.stderr + blocked.stdout)


def test_bootstrap_dry_run_does_not_create_identity_profile_or_target(tmp_path):
    source = _release_fixture(tmp_path)
    install = tmp_path / "apps" / "current"

    completed = _run_installer(source, install, "-DryRun")

    assert completed.returncode == 0, completed.stderr
    assert "bootstrap_status=DRY_RUN" in completed.stdout
    assert "identity_profile_created=false" in completed.stdout
    assert "elevation_points=1:code_placement" in completed.stdout
    assert not install.exists()
    assert list(tmp_path.rglob("producer_identity.json")) == []
    assert list(tmp_path.rglob("runtime-profile.json")) == []


def test_bootstrap_places_exact_bytes_records_integrity_and_reuses(tmp_path):
    source = _release_fixture(tmp_path)
    install = tmp_path / "apps" / "current"

    first = _run_installer(source, install)
    second = _run_installer(source, install)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert "bootstrap_status=PASS" in first.stdout
    assert "bootstrap_status=REUSED" in second.stdout
    assert "acl_readback_status=NOT_TESTED" in first.stdout
    assert "acl_readback_status=NOT_TESTED" in second.stdout
    record = json.loads((install / "bootstrap-integrity.json").read_text(encoding="utf-8"))
    assert record["schema_version"] == "container-audit-bootstrap-integrity-v1"
    assert record["status"] == "PASS"
    assert record["identity_profile_created"] is False
    assert record["state_scope"] == "current_user_first_run"
    by_path = {entry["path"]: entry for entry in record["files"]}
    assert set(by_path) == {"Container_Audit.exe", "contract.lock.json", "runtime.dll"}
    for relative_path, item in by_path.items():
        payload = (install / relative_path).read_bytes()
        assert item["size"] == len(payload)
        assert item["sha256"] == hashlib.sha256(payload).hexdigest()
        assert payload == (source / relative_path).read_bytes()
    assert not (install / "producer_identity.json").exists()
    assert not (install / "runtime-profile.json").exists()
    (install / "runtime.dll").write_bytes(b"tampered-after-placement")
    damaged = _run_installer(source, install)
    assert damaged.returncode != 0
    assert "different or damaged hardened code placement" in (
        damaged.stderr + damaged.stdout
    )


def test_bootstrap_copies_opt_in_tls_ca_for_current_user_onboarding(tmp_path):
    source = _release_fixture(tmp_path)
    install = tmp_path / "apps" / "current"
    local_app_data = tmp_path / "operator" / "LocalAppData"
    ca_source = tmp_path / "operator stage" / "private-ca.cert.pem"
    ca_source.parent.mkdir(parents=True)
    ca_payload = _private_ca_pem()
    ca_source.write_bytes(ca_payload)

    completed = _run_installer(
        source,
        install,
        "-TlsCaBundlePath",
        str(ca_source),
        "-OperatorLocalAppDataRoot",
        str(local_app_data),
    )

    expected = (
        local_app_data / "KMTech" / "Bootstrap" / "Container_Audit" / "ca-bundle.pem"
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert "tls_ca_bootstrap_status=PASS" in completed.stdout
    assert f"tls_ca_bootstrap_path={expected}" in completed.stdout
    assert expected.read_bytes() == ca_payload


def test_bootstrap_refuses_implicit_replacement_and_inverse_preserves_user_state(tmp_path):
    source = _release_fixture(tmp_path)
    install = tmp_path / "apps" / "current"
    user_state = tmp_path / "LocalAppData" / "KMTech" / "ContainerAudit" / "ledger.db"
    user_state.parent.mkdir(parents=True)
    user_state.write_bytes(b"preserve-me")
    assert _run_installer(source, install).returncode == 0
    (source / "Container_Audit.exe").write_bytes(b"different-release")

    conflict = _run_installer(source, install)

    assert conflict.returncode != 0
    # Windows PowerShell may hard-wrap stderr in the middle of words.  The
    # semantic diagnostic must still be present after removing presentation
    # whitespace introduced by the host.
    conflict_text = "".join((conflict.stderr + conflict.stdout).split()).lower()
    assert "differentordamagedhardenedcodeplacementexists" in conflict_text
    removed = _run_installer(source, install, "-Uninstall")
    assert removed.returncode == 0, removed.stderr
    assert "uninstall_status=PASS_CODE_REMOVED_STATE_PRESERVED" in removed.stdout
    assert not install.exists()
    assert user_state.read_bytes() == b"preserve-me"

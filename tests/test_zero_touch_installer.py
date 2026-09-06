import hashlib
import json
import os
import re
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
WRITER_SESSION_ADAPTER = ROOT / "tools" / "container_writer_session.ps1"
WRITER_SESSION_CONTRACT = ROOT / "tools" / "container_writer_session_contract.json"
WRITER_FENCE_HELPER = ROOT / "tools" / "container_writer_fence.ps1"
WRITER_SINK_INVENTORY = ROOT / "tools" / "container_writer_sink_inventory.json"


def _powershell() -> str:
    executable = shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell is required")
    return executable


def _run_installer(source_root: Path, install_root: Path, *extra: str):
    environment = dict(os.environ)
    environment["KMTECH_FACTORY_INSTALL_TEST_MODE"] = "1"
    package_helper = source_root / "INSTALL_THIS_PC.ps1"
    installer_path = package_helper if package_helper.is_file() else INSTALLER
    return subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer_path),
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


def _run_restore(
    install_root: Path,
    receipt: Path,
    receipt_sha256: str,
    transaction_id: str,
    evidence: Path,
    *extra: str,
):
    environment = dict(os.environ)
    environment["KMTECH_FACTORY_INSTALL_TEST_MODE"] = "1"
    installer_path = install_root / "INSTALL_THIS_PC.ps1"
    return subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer_path),
            "-InstallRoot",
            str(install_root),
            "-AllowNoncanonicalLayoutForTest",
            "-RestoreVerifiedReplacement",
            "-ReplacementTransactionId",
            transaction_id,
            "-ReplacementReceiptPath",
            str(receipt),
            "-ReplacementReceiptSha256",
            receipt_sha256,
            "-RestoreEvidencePath",
            str(evidence),
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )


def _output_value(output: str, name: str) -> str:
    prefix = f"{name}="
    values = [line[len(prefix) :] for line in output.splitlines() if line.startswith(prefix)]
    assert len(values) == 1, (name, output)
    return values[0]


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


def _portable_release_fixture(
    root: Path,
    *,
    directory: str = "portable release 한글",
    source_commit: str = "a" * 40,
    main_payload: str = "# portable main\n",
) -> Path:
    release = root / directory
    (release / "runtime").mkdir(parents=True)
    (release / "app").mkdir()
    (release / "runtime" / "python.exe").write_bytes(b"signed-python-test-double")
    pythonw = b"signed-pythonw-test-double"
    (release / "runtime" / "pythonw.exe").write_bytes(pythonw)
    (release / "app" / "main.py").write_text(main_payload, encoding="utf-8")
    launcher = b"@echo off\r\n"
    (release / "launch-container-audit.cmd").write_bytes(launcher)
    (release / "tools").mkdir()
    shutil.copy2(PORTABLE_INSTALLER, release / "INSTALL_CANONICAL_PORTABLE.ps1")
    shutil.copy2(INSTALLER, release / "INSTALL_THIS_PC.ps1")
    shutil.copy2(INTEGRITY_HELPER, release / "tools" / "bootstrap_integrity.ps1")
    shutil.copy2(
        WRITER_SESSION_ADAPTER,
        release / "tools" / "container_writer_session.ps1",
    )
    shutil.copy2(
        WRITER_SESSION_CONTRACT,
        release / "tools" / "container_writer_session_contract.json",
    )
    shutil.copy2(
        WRITER_FENCE_HELPER,
        release / "tools" / "container_writer_fence.ps1",
    )
    shutil.copy2(
        WRITER_SINK_INVENTORY,
        release / "tools" / "container_writer_sink_inventory.json",
    )
    files = [path for path in release.rglob("*") if path.is_file()]
    manifest = {
        "schema": "container-audit-portable-tree-v1",
        "source_commit": source_commit,
        "source_tree": "b" * 40,
        "entrypoint": "runtime/pythonw.exe app/main.py",
        "launcher": "launch-container-audit.cmd",
        "runtime_pythonw_sha256": hashlib.sha256(pythonw).hexdigest(),
        "launcher_sha256": hashlib.sha256(launcher).hexdigest(),
        "installer_sha256": hashlib.sha256(
            (release / "INSTALL_CANONICAL_PORTABLE.ps1").read_bytes()
        ).hexdigest(),
        "helper_sha256": hashlib.sha256(
            (release / "INSTALL_THIS_PC.ps1").read_bytes()
        ).hexdigest(),
        "integrity_helper_sha256": hashlib.sha256(
            (release / "tools" / "bootstrap_integrity.ps1").read_bytes()
        ).hexdigest(),
        "writer_fence_helper_path": "tools/container_writer_fence.ps1",
        "writer_fence_helper_sha256": hashlib.sha256(
            (release / "tools" / "container_writer_fence.ps1").read_bytes()
        ).hexdigest(),
        "writer_session_adapter_path": "tools/container_writer_session.ps1",
        "writer_session_adapter_sha256": hashlib.sha256(
            (release / "tools" / "container_writer_session.ps1").read_bytes()
        ).hexdigest(),
        "writer_session_contract_path": "tools/container_writer_session_contract.json",
        "writer_session_contract_schema": (
            "container-audit-writer-session-cli-contract-v1"
        ),
        "writer_session_contract_sha256": hashlib.sha256(
            (release / "tools" / "container_writer_session_contract.json").read_bytes()
        ).hexdigest(),
        "writer_sink_inventory_path": "tools/container_writer_sink_inventory.json",
        "writer_sink_inventory_sha256": hashlib.sha256(
            (release / "tools" / "container_writer_sink_inventory.json").read_bytes()
        ).hexdigest(),
        "writer_sink_inventory_contract_sha256": json.loads(
            (release / "tools" / "container_writer_sink_inventory.json").read_text(
                encoding="utf-8"
            )
        )["inventory_sha256"],
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


def test_direct_production_helper_requires_exact_writer_delegation_before_elevation():
    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(INSTALLER),
            "-RestoreVerifiedReplacement",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "exact attempt-bound writer fence parameters" in (
        completed.stdout + completed.stderr
    )
    assert "Elevated Container verified replacement restore started" not in (
        completed.stdout + completed.stderr
    )


def test_direct_production_helper_rejects_well_formed_but_inactive_delegation(
    tmp_path,
):
    environment = dict(os.environ)
    environment["LOCALAPPDATA"] = str(tmp_path / "local-app-data")
    writer_fence_sha256 = hashlib.sha256(WRITER_FENCE_HELPER.read_bytes()).hexdigest()
    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(INSTALLER),
            "-RestoreVerifiedReplacement",
            "-WriterFenceHelperPath",
            str(WRITER_FENCE_HELPER),
            "-ExpectedWriterFenceHelperSha256",
            writer_fence_sha256,
            "-WriterFenceSessionId",
            "1" * 32,
            "-WriterFenceAttemptId",
            "2" * 32,
            "-WriterFenceReplacementTransactionId",
            "3" * 32,
            "-WriterFenceDelegationToken",
            "4" * 64,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert completed.returncode != 0
    assert "CONTAINER_WRITER_FENCE_" in completed.stdout + completed.stderr
    assert "Elevated Container verified replacement restore started" not in (
        completed.stdout + completed.stderr
    )










def test_bootstrap_task_query_failure_stops_without_task_mutation():
    environment = dict(os.environ)
    environment["KMTECH_TEST_INSTALLER_PATH"] = str(INSTALLER)
    command = r"""
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:KMTECH_TEST_INSTALLER_PATH,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { exit 10 }
foreach ($name in @('Get-LegacyTaskByNameFailClosed','Remove-OwnedLegacyTask')) {
    $functions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { exit 11 }
    Invoke-Expression $functions[0].Extent.Text
}
$script:stopCalls = 0
$script:unregisterCalls = 0
function Get-ScheduledTask {
    [CmdletBinding()]
    param()
    throw [InvalidOperationException]::new('injected provider failure')
}
function Stop-ScheduledTask { $script:stopCalls += 1 }
function Unregister-ScheduledTask { $script:unregisterCalls += 1 }
try {
    Remove-OwnedLegacyTask 'direct-sync-relay-container-audit' 'C:\expected'
    exit 12
}
catch {
    if (-not $_.Exception.Message.StartsWith(
        'Legacy scheduled task observation failed:',
        [StringComparison]::Ordinal
    )) { exit 13 }
}
if ($script:stopCalls -ne 0 -or $script:unregisterCalls -ne 0) { exit 14 }
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


def test_portable_rollback_product_failure_records_explicit_failure_without_restore():
    text = PORTABLE_INSTALLER.read_text(encoding="utf-8")
    initialization = text.index("$audit.rollback.runtime_restored = (-not $mutated)")
    product = text.index("Product $install '--remove-current-user-setup'", initialization)
    success = text.index("$audit.rollback.runtime_restored = $true", product)
    assert initialization < product < success
    assert "try{Product $install '--remove-current-user-setup'}catch{}" not in text

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
if ($errors.Count -ne 0) { exit 20 }
$candidates = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and
        $node.Extent.Text.Contains("Product `$install '--remove-current-user-setup'") -and
        $node.Extent.Text.Contains("`$audit.status = 'AUTOSTART_ROLLBACK_FAILED'") -and
        -not $node.Extent.Text.Contains('Enable-CanonicalWriter')
}, $true))
if ($candidates.Count -ne 1) { exit 21 }
$script:productCalls = 0
$script:restoreCalls = 0
$script:startCalls = 0
$script:saveCalls = 0
$script:syncCalls = 0
function Sync-CanonicalWriterFenceInventory { $script:syncCalls += 1 }
function Product {
    param($Root, $Mode)
    $script:productCalls += 1
    throw [InvalidOperationException]::new('injected rollback removal failure')
}
function Restore { $script:restoreCalls += 1 }
function StartRaw { $script:startCalls += 1; return 1234 }
function Save { $script:saveCalls += 1 }
$mutated = $true
$codeRollbackFailure = ''
$install = 'C:\unused'
$before = [pscustomobject]@{ exists=$false; kind=''; data='' }
$stop = 'C:\unused\stop.json'
$old = @()
$auditPath = 'C:\unused\audit.json'
$evidenceFull = ''
$autostartRollbackFailure = ''
$audit = [ordered]@{
    status = ''
    failure_type = ''
    rollback = [ordered]@{ applied=$true; runtime_restored=$false }
}
try { throw [ApplicationException]::new('original failure') }
catch { $original = $_ }
Invoke-Expression $candidates[0].Extent.Text
if ($script:productCalls -ne 1) { exit 22 }
if ($script:syncCalls -ne 1) { exit 28 }
if ($script:restoreCalls -ne 0 -or $script:startCalls -ne 0) { exit 23 }
if ([bool]$audit.rollback.runtime_restored) { exit 24 }
if ([string]$audit.status -cne 'AUTOSTART_ROLLBACK_FAILED') { exit 25 }
if ([string]::IsNullOrWhiteSpace($autostartRollbackFailure)) { exit 26 }
if ($script:saveCalls -ne 1) { exit 27 }
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


def test_portable_installer_validates_runtime_binding_before_preimage_acceptance():
    text = PORTABLE_INSTALLER.read_text(encoding="utf-8")
    capture_index = text.index("$old = @(Relays)")
    validation_index = text.index(
        "$runtimePreimageBinding = Assert-CanonicalRuntimePreimage", capture_index
    )
    audit_index = text.index("$audit = [ordered]@{", validation_index)
    save_index = text.index("Save $auditPath $audit", audit_index)
    disable_index = text.index("$writerDisabled = Disable-CanonicalWriter", save_index)
    assert capture_index < validation_index < audit_index < save_index < disable_index

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
foreach ($name in @('Full','Same','Get-CanonicalRelayCommandIdentity','Assert-CanonicalRuntimePreimage')) {
    $functions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { exit 11 }
    Invoke-Expression $functions[0].Extent.Text
}
$script:mutationCalls = 0
function Product { $script:mutationCalls += 1 }
function Restore { $script:mutationCalls += 1 }
function StartRaw { $script:mutationCalls += 1 }
function Save { $script:mutationCalls += 1 }
function Set-ItemProperty { $script:mutationCalls += 1 }
function Remove-ItemProperty { $script:mutationCalls += 1 }
function Start-Process { $script:mutationCalls += 1 }
function Stop-Process { $script:mutationCalls += 1 }
$root = 'C:\KMTech\Apps\Container_Audit\current'
$command = 'C:\KMTech\Apps\Container_Audit\current\runtime\pythonw.exe -I -B C:\KMTech\Apps\Container_Audit\current\app\main.py --container-audit-user-relay'
$validBefore = [ordered]@{ exists=$true; kind='String'; data=$command }
$validProcess = New-CimInstance -ClassName Win32_Process -ClientOnly -Property @{
    ExecutablePath='C:\KMTech\Apps\Container_Audit\current\runtime\pythonw.exe'
    CommandLine=$command
}
$wrongBefore = [ordered]@{ exists=$true; kind='String'; data='C:\foreign\pythonw.exe --container-audit-user-relay' }
$foreign = New-CimInstance -ClassName Win32_Process -ClientOnly -Property @{
    ExecutablePath='C:\foreign\pythonw.exe'
    CommandLine=$command
}
$orderedType = 'System.Collections.Specialized.OrderedDictionary'
$cimType = 'Microsoft.Management.Infrastructure.CimInstance'
if (
    $validBefore.GetType().FullName -cne $orderedType -or
    $wrongBefore.GetType().FullName -cne $orderedType
) { exit 12 }
if (
    $validProcess.GetType().FullName -cne $cimType -or
    $foreign.GetType().FullName -cne $cimType
) { exit 13 }
$valid = Assert-CanonicalRuntimePreimage $validBefore @($validProcess) $command $root $false
if ($valid.GetType().FullName -cne $orderedType) { exit 14 }
if ([string]$valid.status -cne 'PASS' -or [int]$valid.relay_count -ne 1) { exit 15 }
try {
    [void](Assert-CanonicalRuntimePreimage $wrongBefore @() $command $root $false)
    exit 16
}
catch {
    if ($_.Exception.Message -cne 'CANONICAL_HKCU_RUN_BINDING_MISMATCH') { exit 17 }
}
try {
    [void](Assert-CanonicalRuntimePreimage $validBefore @($foreign) $command $root $false)
    exit 18
}
catch {
    if ($_.Exception.Message -cne 'CANONICAL_RELAY_BINDING_MISMATCH') { exit 19 }
}
try {
    [void](Assert-CanonicalRuntimePreimage $validBefore @($validProcess) $command $root $true)
    exit 20
}
catch {
    if ($_.Exception.Message -cne 'CANONICAL_STOP_MARKER_PREEXISTS') { exit 21 }
}
if ($script:mutationCalls -ne 0) { exit 22 }
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


@pytest.mark.parametrize(
    "spelling,accepted",
    [
        ("canonical", True),
        ("autostart_quoted_executable", True),
        ("different_executable", False),
        ("executable_case", False),
        ("different_entrypoint", False),
        ("entrypoint_case", False),
        ("argument_case", False),
        ("extra_argument", False),
        ("missing_argument", False),
        ("quoted_arguments", False),
        ("quote_spans_arguments", False),
        ("missing_executable_quote", False),
        ("missing_token_boundary", False),
    ],
)
def test_portable_runtime_binding_accepts_only_executable_quote_spelling(
    spelling, accepted,
):
    executable = r"C:\KMTech\Apps\Container_Audit\current\runtime\pythonw.exe"
    arguments = (
        r" -I -B C:\KMTech\Apps\Container_Audit\current\app\main.py"
        " --container-audit-user-relay"
    )
    canonical = executable + arguments
    quoted = '"' + executable + '"' + arguments
    commands = {
        "canonical": canonical,
        "autostart_quoted_executable": quoted,
        "different_executable": quoted.replace("pythonw.exe", "python.exe"),
        "executable_case": quoted.replace("pythonw.exe", "PYTHONW.EXE"),
        "different_entrypoint": quoted.replace("main.py", "foreign.py"),
        "entrypoint_case": quoted.replace("main.py", "MAIN.PY"),
        "argument_case": quoted.replace(" -I ", " -i "),
        "extra_argument": quoted + " --foreign",
        "missing_argument": quoted.replace(" -B ", " "),
        "quoted_arguments": '"' + executable + '" "' + arguments[1:] + '"',
        "quote_spans_arguments": '"' + executable + ' -I"' + arguments[3:],
        "missing_executable_quote": '"' + canonical,
        "missing_token_boundary": '"' + executable + '"' + arguments[1:],
    }
    environment = dict(os.environ)
    environment.update(
        KMTECH_TEST_INSTALLER_PATH=str(PORTABLE_INSTALLER),
        KMTECH_TEST_RELAY_COMMAND=commands[spelling],
        KMTECH_TEST_RELAY_ACCEPTED=str(int(accepted)),
    )
    command = r'''
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:KMTECH_TEST_INSTALLER_PATH, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw 'Installer parse failed' }
# Load definitions only, so the real guard runs without the installer entrypoint.
foreach ($definition in $ast.EndBlock.Statements) {
    if ($definition -is [Management.Automation.Language.FunctionDefinitionAst]) {
        Invoke-Expression $definition.Extent.Text
    }
}
$root = 'C:\KMTech\Apps\Container_Audit\current'
$expected = Command $root
$before = [ordered]@{ exists=$true; kind='String'; data=$expected }
$process = New-CimInstance -ClassName Win32_Process -ClientOnly -Property @{
    ExecutablePath=(Join-Path $root 'runtime\pythonw.exe')
    CommandLine=$env:KMTECH_TEST_RELAY_COMMAND
}
$failure = ''
try { $result = Assert-CanonicalRuntimePreimage $before @($process) $expected $root $false }
catch { $failure = $_.Exception.Message }
if ($env:KMTECH_TEST_RELAY_ACCEPTED -ceq '1') {
    if ($failure) { throw $failure }
    if ($result.status -cne 'PASS' -or $result.relay_count -ne 1) { throw 'Binding did not pass' }
}
elseif ($failure -cne 'CANONICAL_RELAY_BINDING_MISMATCH') {
    throw "Expected relay binding rejection, got: $failure"
}
'''
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False, capture_output=True, text=True, timeout=60, env=environment,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_portable_rollback_relay_guard_executes_exact_negative_rows_without_mutation():
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
foreach ($name in @('Full','Same','Assert-RollbackRelayPreimage')) {
    $functions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { exit 11 }
    Invoke-Expression $functions[0].Extent.Text
}
$script:scenario = ''
$script:readCalls = 0
$script:mutationCalls = 0
function Product { $script:mutationCalls += 1 }
function Restore { $script:mutationCalls += 1 }
function StartRaw { $script:mutationCalls += 1 }
function Save { $script:mutationCalls += 1 }
function Set-ItemProperty { $script:mutationCalls += 1 }
function Remove-ItemProperty { $script:mutationCalls += 1 }
function Start-Process { $script:mutationCalls += 1 }
function Stop-Process { $script:mutationCalls += 1 }
function New-SyntheticRelay([string]$ExecutablePath, [string]$CommandLine) {
    return New-CimInstance -ClassName Win32_Process -ClientOnly -Property @{
        ExecutablePath = $ExecutablePath
        CommandLine = $CommandLine
    }
}
$expectedCommand = 'C:\KMTech\Apps\Container_Audit\current\runtime\pythonw.exe --container-audit-user-relay'
$script:expectedRow = New-SyntheticRelay 'C:\KMTech\Apps\Container_Audit\current\runtime\pythonw.exe' $expectedCommand
$script:extraRow = New-SyntheticRelay 'C:\KMTech\Apps\Container_Audit\other\runtime\pythonw.exe' 'pythonw.exe --container-audit-user-relay --extra'
$script:mismatchRow = New-SyntheticRelay 'C:\KMTech\Apps\Container_Audit\current\runtime\pythonw.exe' ($expectedCommand + ' --different')
$cimType = 'Microsoft.Management.Infrastructure.CimInstance'
foreach ($row in @($script:expectedRow, $script:extraRow, $script:mismatchRow)) {
    if ($row.GetType().FullName -cne $cimType) { exit 12 }
}
function Relays {
    $script:readCalls += 1
    switch -CaseSensitive ($script:scenario) {
        'exact' { return @($script:expectedRow) }
        'extra' { return @($script:expectedRow, $script:extraRow) }
        'mismatch' { return @($script:mismatchRow) }
        'query_error' { throw [InvalidOperationException]::new('injected relay inventory failure') }
        default { throw [InvalidOperationException]::new('unexpected harness scenario') }
    }
}
$script:scenario = 'exact'
$exact = @(Assert-RollbackRelayPreimage -ExpectedRelays @($script:expectedRow))
if ($exact.Count -ne 1 -or $exact[0].GetType().FullName -cne $cimType) { exit 13 }
$script:scenario = 'extra'
try {
    [void](Assert-RollbackRelayPreimage -ExpectedRelays @($script:expectedRow))
    exit 14
}
catch {
    if ($_.Exception.Message -cne 'rollback relay process-count readback failed') { exit 15 }
}
$script:scenario = 'mismatch'
try {
    [void](Assert-RollbackRelayPreimage -ExpectedRelays @($script:expectedRow))
    exit 16
}
catch {
    if ($_.Exception.Message -cne 'rollback relay executable/command readback failed') { exit 17 }
}
$script:scenario = 'query_error'
try {
    [void](Assert-RollbackRelayPreimage -ExpectedRelays @())
    exit 18
}
catch {
    if ($_.Exception.Message -cne 'injected relay inventory failure') { exit 19 }
}
if ($script:readCalls -ne 4) { exit 20 }
if ($script:mutationCalls -ne 0) { exit 21 }
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout




def test_portable_installer_test_mode_terminal_status_is_explicitly_nonproduction():
    text = PORTABLE_INSTALLER.read_text(encoding="utf-8")
    assert (
        "$audit.status=if ($testMode) { 'TEST_ONLY_PARTIAL' } "
        "else { 'PRODUCT_PHASE_PASS' }"
    ) in text
    assert "$audit.status=$terminalStatus" in text
    assert '"install_status=$terminalStatus"' in text
    assert "$audit.status='PASS'" not in text
    assert "'install_status=PASS'" not in text

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
        $node.Name -ceq 'Get-CanonicalInstallSuccessStatus'
}, $true))
if ($functions.Count -ne 1) { exit 11 }
Invoke-Expression $functions[0].Extent.Text
if ((Get-CanonicalInstallSuccessStatus $false) -cne 'PASS') { exit 12 }
if ((Get-CanonicalInstallSuccessStatus $true) -cne 'TEST_ONLY_PARTIAL') { exit 13 }
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_portable_receipt_readers_require_exact_shapes_and_json_scalar_types(tmp_path):
    transaction_id = "1" * 32
    source_commit = "a" * 40
    source_tree = "b" * 40
    helper_sha256 = "c" * 64
    integrity_helper_sha256 = "d" * 64
    manifest_sha256 = "e" * 64
    restore_receipt_sha256 = "f" * 64
    install_root = tmp_path / "apps" / "current"
    install_parent = install_root.parent

    def tree(seed: str, *, commit: str, source: str, manifest: str) -> dict:
        return {
            "file_count": 3,
            "aggregate_sha256": seed * 64,
            "integrity_sha256": chr(ord(seed) + 1) * 64,
            "manifest_sha256": manifest,
            "source_commit": commit,
            "source_tree": source,
            "owner_sid": "S-1-5-32-544",
            "access_rules_protected": True,
            "acl_sddl_sha256": chr(ord(seed) + 2) * 64,
            "reparse_count": 0,
        }

    replacement_template = {
        "schema_version": "container-audit-verified-replacement-v1",
        "status": "OLD_PRESERVED_NEW_VERIFIED",
        "app_id": "container_audit",
        "transaction_id": transaction_id,
        "created_at": "2026-08-30T00:00:00.0000000Z",
        "helper_sha256": helper_sha256,
        "integrity_helper_sha256": integrity_helper_sha256,
        "receipt_path": "",
        "install_root": str(install_root),
        "install_parent": str(install_parent),
        "rollback_root": str(install_parent / f".current.rollback.{transaction_id}"),
        "failed_root": str(install_parent / f".current.failed.{transaction_id}"),
        "parent_acl": {
            "owner_sid": "S-1-5-32-544",
            "access_rules_protected": True,
            "sddl_sha256": "9" * 64,
        },
        "old": tree("1", commit="2" * 40, source="3" * 40, manifest="4" * 64),
        "new": tree(
            "5", commit=source_commit, source=source_tree, manifest=manifest_sha256
        ),
        "identity_or_credential_copied": False,
    }

    def clone(value: dict) -> dict:
        return json.loads(json.dumps(value))

    def write_replacement(name: str, mutate=None) -> Path:
        path = tmp_path / "validator-fixtures" / f"replacement-{name}.json"
        payload = clone(replacement_template)
        payload["receipt_path"] = str(path)
        if mutate:
            mutate(payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
        return path

    valid_replacement = write_replacement("valid")
    replacement_string_zero = write_replacement(
        "string-zero",
        lambda payload: payload["old"].__setitem__("reparse_count", "0"),
    )
    replacement_nested_string_false = write_replacement(
        "nested-string-false",
        lambda payload: payload["old"].__setitem__(
            "access_rules_protected", "false"
        ),
    )
    replacement_top_string_false = write_replacement(
        "top-string-false",
        lambda payload: payload.__setitem__(
            "identity_or_credential_copied", "false"
        ),
    )
    replacement_extra = write_replacement(
        "extra",
        lambda payload: payload.__setitem__("observation_status", "SNAPSHOT_ERROR"),
    )

    def remove_parent_acl_hash(payload: dict) -> None:
        del payload["parent_acl"]["sddl_sha256"]

    replacement_missing_nested = write_replacement(
        "missing-nested", remove_parent_acl_hash
    )

    restore_template = {
        "schema_version": "container-audit-verified-replacement-code-restore-v1",
        "status": "PASS",
        "action": "RESTORED",
        "app_id": "container_audit",
        "transaction_id": transaction_id,
        "receipt_path": str(valid_replacement),
        "receipt_sha256": restore_receipt_sha256,
        "install_root": str(install_root),
        "failed_new_root": str(
            install_parent / f".current.failed.{transaction_id}"
        ),
        "prior_code_exact": True,
        "failed_new_preserved": True,
        "identity_or_credential_copied": False,
        "completed_at": "2026-08-30T00:01:00.0000000Z",
    }

    def write_restore(name: str, mutate=None) -> Path:
        path = tmp_path / "validator-fixtures" / f"restore-{name}.json"
        payload = clone(restore_template)
        if mutate:
            mutate(payload)
        path.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
        return path

    valid_restore = write_restore("valid")
    restore_prior_string_false = write_restore(
        "prior-string-false",
        lambda payload: payload.__setitem__("prior_code_exact", "false"),
    )
    restore_failed_string_false = write_restore(
        "failed-string-false",
        lambda payload: payload.__setitem__("failed_new_preserved", "false"),
    )
    restore_identity_string_false = write_restore(
        "identity-string-false",
        lambda payload: payload.__setitem__(
            "identity_or_credential_copied", "false"
        ),
    )
    restore_extra = write_restore(
        "extra",
        lambda payload: payload.__setitem__(
            "observation_status", "SNAPSHOT_ERROR"
        ),
    )

    def remove_completed_at(payload: dict) -> None:
        del payload["completed_at"]

    restore_missing = write_restore("missing", remove_completed_at)

    assert json.loads(replacement_string_zero.read_text(encoding="utf-8"))["old"][
        "reparse_count"
    ] == "0"
    assert json.loads(restore_prior_string_false.read_text(encoding="utf-8"))[
        "prior_code_exact"
    ] == "false"

    environment = dict(os.environ)
    environment.update(
        {
            "KMTECH_TEST_INSTALLER_PATH": str(PORTABLE_INSTALLER),
            "KMTECH_TEST_VALID_REPLACEMENT": str(valid_replacement),
            "KMTECH_TEST_REPLACEMENT_STRING_ZERO": str(replacement_string_zero),
            "KMTECH_TEST_REPLACEMENT_NESTED_STRING_FALSE": str(
                replacement_nested_string_false
            ),
            "KMTECH_TEST_REPLACEMENT_TOP_STRING_FALSE": str(
                replacement_top_string_false
            ),
            "KMTECH_TEST_REPLACEMENT_EXTRA": str(replacement_extra),
            "KMTECH_TEST_REPLACEMENT_MISSING_NESTED": str(
                replacement_missing_nested
            ),
            "KMTECH_TEST_VALID_RESTORE": str(valid_restore),
            "KMTECH_TEST_RESTORE_PRIOR_STRING_FALSE": str(
                restore_prior_string_false
            ),
            "KMTECH_TEST_RESTORE_FAILED_STRING_FALSE": str(
                restore_failed_string_false
            ),
            "KMTECH_TEST_RESTORE_IDENTITY_STRING_FALSE": str(
                restore_identity_string_false
            ),
            "KMTECH_TEST_RESTORE_EXTRA": str(restore_extra),
            "KMTECH_TEST_RESTORE_MISSING": str(restore_missing),
            "KMTECH_TEST_INSTALL_ROOT": str(install_root),
            "KMTECH_TEST_TRANSACTION_ID": transaction_id,
            "KMTECH_TEST_SOURCE_COMMIT": source_commit,
            "KMTECH_TEST_SOURCE_TREE": source_tree,
            "KMTECH_TEST_HELPER_SHA256": helper_sha256,
            "KMTECH_TEST_INTEGRITY_HELPER_SHA256": integrity_helper_sha256,
            "KMTECH_TEST_MANIFEST_SHA256": manifest_sha256,
            "KMTECH_TEST_RESTORE_RECEIPT_SHA256": restore_receipt_sha256,
        }
    )
    command = r"""
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:KMTECH_TEST_INSTALLER_PATH,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) { exit 10 }
foreach ($name in @(
    'Full','Same','Test-ExactPropertySet','Test-ExactStringProperties',
    'Test-JsonInteger','ReadReplacementReceipt','ReadReplacementRestoreEvidence'
)) {
    $functions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { exit 11 }
    Invoke-Expression $functions[0].Extent.Text
}
$manifest = [pscustomobject]@{
    source_commit = $env:KMTECH_TEST_SOURCE_COMMIT
    source_tree = $env:KMTECH_TEST_SOURCE_TREE
}
$replacement = ReadReplacementReceipt `
    $env:KMTECH_TEST_VALID_REPLACEMENT `
    $env:KMTECH_TEST_TRANSACTION_ID `
    $env:KMTECH_TEST_INSTALL_ROOT `
    $manifest `
    $env:KMTECH_TEST_MANIFEST_SHA256 `
    $env:KMTECH_TEST_HELPER_SHA256 `
    $env:KMTECH_TEST_INTEGRITY_HELPER_SHA256
if ([string]$replacement.status -cne 'OLD_PRESERVED_NEW_VERIFIED') { exit 12 }
foreach ($path in @(
    $env:KMTECH_TEST_REPLACEMENT_STRING_ZERO,
    $env:KMTECH_TEST_REPLACEMENT_NESTED_STRING_FALSE,
    $env:KMTECH_TEST_REPLACEMENT_TOP_STRING_FALSE,
    $env:KMTECH_TEST_REPLACEMENT_EXTRA,
    $env:KMTECH_TEST_REPLACEMENT_MISSING_NESTED
)) {
    try {
        [void](ReadReplacementReceipt `
            $path `
            $env:KMTECH_TEST_TRANSACTION_ID `
            $env:KMTECH_TEST_INSTALL_ROOT `
            $manifest `
            $env:KMTECH_TEST_MANIFEST_SHA256 `
            $env:KMTECH_TEST_HELPER_SHA256 `
            $env:KMTECH_TEST_INTEGRITY_HELPER_SHA256)
        exit 13
    }
    catch {
        if ($_.Exception.Message -cne 'Verified replacement receipt contract readback failed.') {
            exit 14
        }
    }
}
$restore = ReadReplacementRestoreEvidence `
    $env:KMTECH_TEST_VALID_RESTORE `
    $env:KMTECH_TEST_TRANSACTION_ID `
    $env:KMTECH_TEST_VALID_REPLACEMENT `
    $env:KMTECH_TEST_RESTORE_RECEIPT_SHA256 `
    $env:KMTECH_TEST_INSTALL_ROOT
if ([string]$restore.status -cne 'PASS') { exit 15 }
foreach ($path in @(
    $env:KMTECH_TEST_RESTORE_PRIOR_STRING_FALSE,
    $env:KMTECH_TEST_RESTORE_FAILED_STRING_FALSE,
    $env:KMTECH_TEST_RESTORE_IDENTITY_STRING_FALSE,
    $env:KMTECH_TEST_RESTORE_EXTRA,
    $env:KMTECH_TEST_RESTORE_MISSING
)) {
    try {
        [void](ReadReplacementRestoreEvidence `
            $path `
            $env:KMTECH_TEST_TRANSACTION_ID `
            $env:KMTECH_TEST_VALID_REPLACEMENT `
            $env:KMTECH_TEST_RESTORE_RECEIPT_SHA256 `
            $env:KMTECH_TEST_INSTALL_ROOT)
        exit 16
    }
    catch {
        if ($_.Exception.Message -cne 'Verified replacement restore evidence contract readback failed.') {
            exit 17
        }
    }
}
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_portable_runtime_json_scalar_guards_reject_string_false_and_zero():
    text = PORTABLE_INSTALLER.read_text(encoding="utf-8")
    assert "if(Test-JsonTrue $relay.persistent_retry){break}" in text
    assert (
        "if($null-eq$relay -or -not (Test-JsonTrue "
        "$relay.persistent_retry)){throw 'Fresh relay status proof failed.'}"
    ) in text
    assert "[bool]$relay.persistent_retry" not in text
    assert (
        "Test-JsonPositiveInt32 $onboarding.relay_start.process_id"
    ) in text
    assert (
        "Test-JsonTrue "
        "$contract.lifecycle_restore.require_lifecycle_restore_before_writer_restore"
    ) in text
    assert (
        "Test-JsonTrue $contract.security.active_session_authority_mutex_required"
    ) in text
    assert (
        "Test-JsonTrue "
        "$contract.security.evidence_paths_outside_install_parent_required"
    ) in text

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
foreach ($name in @('Test-JsonInteger','Test-JsonTrue','Test-JsonPositiveInt32')) {
    $functions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { exit 11 }
    Invoke-Expression $functions[0].Extent.Text
}
$payload = @'
{
  "actual_true": true,
  "actual_false": false,
  "string_false": "false",
  "string_zero": "0",
  "actual_pid": 123,
  "string_pid": "123",
  "zero_pid": 0
}
'@ | ConvertFrom-Json
if (-not (Test-JsonTrue $payload.actual_true)) { exit 12 }
if (Test-JsonTrue $payload.actual_false) { exit 13 }
if (Test-JsonTrue $payload.string_false) { exit 14 }
if (Test-JsonTrue $payload.string_zero) { exit 15 }
if (-not (Test-JsonPositiveInt32 $payload.actual_pid)) { exit 16 }
if (Test-JsonPositiveInt32 $payload.string_pid) { exit 17 }
if (Test-JsonPositiveInt32 $payload.string_zero) { exit 18 }
if (Test-JsonPositiveInt32 $payload.zero_pid) { exit 19 }
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


@pytest.mark.parametrize(
    "metric_field", ("file_count_before_manifest", "byte_count_before_manifest")
)
def test_portable_plan_rejects_stringized_manifest_metrics(tmp_path, metric_field):
    source = _portable_release_fixture(tmp_path)
    manifest_path = source / "portable-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    metric = manifest[metric_field]
    assert isinstance(metric, int) and not isinstance(metric, bool)
    manifest[metric_field] = str(metric)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True), encoding="utf-8"
    )
    assert isinstance(
        json.loads(manifest_path.read_text(encoding="utf-8"))[metric_field], str
    )

    install = tmp_path / "apps" / "current"
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
            str(source / "INSTALL_CANONICAL_PORTABLE.ps1"),
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

    assert completed.returncode != 0
    assert "Portable tree metrics differ from the manifest" in (
        completed.stderr + completed.stdout
    )
    assert not install.exists()


@pytest.mark.parametrize(
    ("section", "field"),
    (
        (
            "lifecycle_restore",
            "require_lifecycle_restore_before_writer_restore",
        ),
        ("security", "active_session_authority_mutex_required"),
        ("security", "evidence_paths_outside_install_parent_required"),
    ),
)
def test_portable_plan_rejects_string_false_public_contract_booleans(
    tmp_path, section, field
):
    source = _portable_release_fixture(tmp_path)
    contract_path = source / "tools" / "container_writer_session_contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    assert contract[section][field] is True
    contract[section][field] = "false"
    contract_path.write_text(
        json.dumps(contract, ensure_ascii=True), encoding="utf-8"
    )
    assert (
        json.loads(contract_path.read_text(encoding="utf-8"))[section][field]
        == "false"
    )

    manifest_path = source / "portable-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["writer_session_contract_sha256"] = hashlib.sha256(
        contract_path.read_bytes()
    ).hexdigest()
    files = [
        path
        for path in source.rglob("*")
        if path.is_file()
        and path != manifest_path
        and path.name != "bootstrap-integrity.json"
    ]
    manifest["file_count_before_manifest"] = len(files)
    manifest["byte_count_before_manifest"] = sum(
        path.stat().st_size for path in files
    )
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True), encoding="utf-8"
    )

    install = tmp_path / "apps" / "current"
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
            str(source / "INSTALL_CANONICAL_PORTABLE.ps1"),
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

    assert completed.returncode != 0
    assert "Writer session public contract semantics differ" in (
        completed.stderr + completed.stdout
    )
    assert not install.exists()




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
$script:mutationCalls = 0
function Enable-CanonicalWriter { $script:mutationCalls += 1 }
function Disable-CanonicalWriter { $script:mutationCalls += 1 }
function Start-ScheduledTask { $script:mutationCalls += 1 }
function Stop-ScheduledTask { $script:mutationCalls += 1 }
function Restore { $script:mutationCalls += 1 }
$before = [ordered]@{ binding_sha256 = ('a' * 64) }
$matchingAfter = [ordered]@{
    present = $true
    classification = 'CANONICAL_QUIESCE_RESTORE'
    enabled = $true
    binding_sha256 = ('a' * 64)
}
$after = [ordered]@{
    present = $true
    classification = 'CANONICAL_QUIESCE_RESTORE'
    enabled = $true
    binding_sha256 = ('b' * 64)
}
$orderedType = 'System.Collections.Specialized.OrderedDictionary'
foreach ($row in @($before, $matchingAfter, $after)) {
    if ($row.GetType().FullName -cne $orderedType) { exit 12 }
}
try {
    Assert-CanonicalWriterRestoreReadback $before $matchingAfter
}
catch { exit 13 }
try {
    Assert-CanonicalWriterRestoreReadback $before $after
    exit 14
}
catch {
    if ($_.Exception.Message -cne 'CANONICAL_WRITER_RESTORE_BINDING_MISMATCH') {
        exit 15
    }
}
if ($script:mutationCalls -ne 0) { exit 16 }
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


def test_portable_writer_snapshot_ignores_non_exec_scheduled_task_actions(tmp_path):
    environment = dict(os.environ)
    environment["KMTECH_TEST_INSTALLER_PATH"] = str(PORTABLE_INSTALLER)
    environment["LOCALAPPDATA"] = str(tmp_path / "local")
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
        $node.Name -in @('Full','Get-CanonicalWriterSnapshot')
}, $true))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($functions.Count -ne 2) { exit 11 }
foreach ($function in $functions) { Invoke-Expression $function.Extent.Text }
$script:CanonicalWriterTaskName = 'ContainerAuditDirectSync'
$script:NoncanonicalQualificationTaskName = 'ContainerAuditQualification'
$comAction = [pscustomobject]@{
    CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskComHandlerAction' }
    ClassId = '{00000000-0000-0000-0000-000000000000}'
}
function Get-ScheduledTask {
    return [pscustomobject]@{
        TaskName = 'BuiltInComHandler'
        TaskPath = '\Microsoft\Windows\Test\'
        Actions = @($comAction)
    }
}
$snapshot = Get-CanonicalWriterSnapshot 'C:\not-installed'
if ([string]$snapshot.classification -cne 'CANONICAL_ABSENT_NONCANONICAL_DISABLED') {
    exit 12
}
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_portable_preflight_failure_removes_prepared_writer_session(tmp_path):
    source = _portable_release_fixture(tmp_path)
    installer_path = source / "INSTALL_CANONICAL_PORTABLE.ps1"
    installer = installer_path.read_text(encoding="utf-8")
    # The preimage is now captured before activating the fence. Model a fresh
    # target explicitly instead of reading this test runner's real HKCU state.
    installer = installer.replace(
        "$before = Snapshot\n",
        "function Snapshot { return [ordered]@{exists=$false;kind='';data=''} }\n"
        "function Relays { return @() }\n$before = Snapshot\n",
        1,
    )
    installer = installer.replace(
        "$canonicalWriterFenceAuthority = Enter-ContainerWriterSessionAuthority",
        "$Script:ContainerWriterFenceAdmissionMutexName = 'Local\\KMTech.CA.Test."
        + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:16]
        + "'\n$canonicalWriterFenceAuthority = Enter-ContainerWriterSessionAuthority",
        1,
    )
    marker = "$canonicalWriterFenceActive = $true\n"
    assert installer.count(marker) >= 1
    installer = installer.replace(
        marker,
        marker + "throw 'TEST_INJECTED_PREFLIGHT_FAILURE'\n",
        1,
    )
    installer_path.write_text(installer, encoding="utf-8")
    manifest_path = source / "portable-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["installer_sha256"] = hashlib.sha256(installer_path.read_bytes()).hexdigest()
    files = [
        path
        for path in source.rglob("*")
        if path.is_file()
        and path != manifest_path
        and path.name != "bootstrap-integrity.json"
    ]
    manifest["file_count_before_manifest"] = len(files)
    manifest["byte_count_before_manifest"] = sum(path.stat().st_size for path in files)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=True), encoding="utf-8")

    local_app_data = tmp_path / "local"
    environment = dict(os.environ)
    environment["KMTECH_FACTORY_INSTALL_TEST_MODE"] = "1"
    environment["LOCALAPPDATA"] = str(local_app_data)
    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer_path),
            "-SourceRoot",
            str(source),
            "-InstallRoot",
            str(tmp_path / "apps" / "current"),
            "-AllowNoncanonicalLayoutForTest",
            "-SkipSignatureValidationForTest",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )

    assert completed.returncode != 0
    assert "TEST_INJECTED_PREFLIGHT_FAILURE" in (completed.stderr + completed.stdout)
    control_root = (
        local_app_data / "KMTech" / "DirectSync" / "container_audit" / "control" / "writer-session"
    )
    assert not (control_root / "active.json").exists()
    audit_root = local_app_data / "KMTech" / "ContainerAudit" / "install-audit"
    assert not list(audit_root.glob("canonical-portable-*-writer-prepared.json"))


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
            str(source / "INSTALL_CANONICAL_PORTABLE.ps1"),
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


def test_portable_scripts_refuse_mixed_executable_and_source_packets(tmp_path):
    source = _portable_release_fixture(tmp_path)
    install = tmp_path / "apps" / "current"
    environment = dict(os.environ)
    environment["KMTECH_FACTORY_INSTALL_TEST_MODE"] = "1"

    top = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
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
    helper = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALLER),
            "-SourceRoot",
            str(source),
            "-InstallRoot",
            str(install),
            "-DryRun",
            "-AllowNoncanonicalLayoutForTest",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )

    assert top.returncode != 0
    assert "admitted SourceRoot" in (top.stderr + top.stdout)
    assert helper.returncode != 0
    assert "admitted SourceRoot" in (helper.stderr + helper.stdout)
    assert not install.exists()


def test_portable_plan_rejects_wrong_entrypoint_before_mutation(tmp_path):
    source = _portable_release_fixture(tmp_path)
    manifest_path = source / "portable-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["entrypoint"] = "runtime/python.exe app/main.py"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=True), encoding="utf-8")
    install = tmp_path / "apps" / "current"
    environment = dict(os.environ)
    environment["KMTECH_FACTORY_INSTALL_TEST_MODE"] = "1"

    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(source / "INSTALL_CANONICAL_PORTABLE.ps1"),
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

    assert completed.returncode != 0
    assert "Portable manifest readback failed" in (completed.stderr + completed.stdout)
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


def test_bootstrap_replaces_only_an_integrity_verified_portable_tree(tmp_path):
    first_source = _portable_release_fixture(
        tmp_path,
        directory="portable first",
        source_commit="a" * 40,
        main_payload="# first portable main\n",
    )
    second_source = _portable_release_fixture(
        tmp_path,
        directory="portable second",
        source_commit="b" * 40,
        main_payload="# second portable main\n",
    )
    install = tmp_path / "apps" / "current"
    receipt = tmp_path / "receipts" / "replacement.json"
    transaction_id = "1" * 32
    first = _run_installer(first_source, install)

    replaced = _run_installer(
        second_source,
        install,
        "-ReplaceExistingVerifiedPortable",
        "-ReplacementTransactionId",
        transaction_id,
        "-ReplacementReceiptPath",
        str(receipt),
    )

    assert first.returncode == 0, first.stderr or first.stdout
    assert replaced.returncode == 0, replaced.stderr or replaced.stdout
    assert "bootstrap_status=REPLACED_VERIFIED" in replaced.stdout
    assert "replacement_rollback_status=PRESERVED" in replaced.stdout
    assert "replacement_receipt_status=OLD_PRESERVED_NEW_VERIFIED" in replaced.stdout
    assert _output_value(replaced.stdout, "replacement_receipt_path") == str(receipt)
    assert _output_value(replaced.stdout, "replacement_transaction_id") == transaction_id
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "container-audit-verified-replacement-v1"
    assert payload["status"] == "OLD_PRESERVED_NEW_VERIFIED"
    assert payload["transaction_id"] == transaction_id
    assert payload["identity_or_credential_copied"] is False
    assert (install / "app" / "main.py").read_text(encoding="utf-8") == (
        "# second portable main\n"
    )
    rollback = install.parent / f".current.rollback.{transaction_id}"
    assert rollback.is_dir()
    assert (rollback / "app" / "main.py").read_text(encoding="utf-8") == (
        "# first portable main\n"
    )


def test_bootstrap_later_restore_is_receipt_bound_resumable_and_preserves_failed_new(
    tmp_path,
):
    first_source = _portable_release_fixture(
        tmp_path,
        directory="portable first",
        source_commit="a" * 40,
        main_payload="# first portable main\n",
    )
    second_source = _portable_release_fixture(
        tmp_path,
        directory="portable second",
        source_commit="b" * 40,
        main_payload="# second portable main\n",
    )
    install = tmp_path / "apps" / "current"
    receipt = tmp_path / "receipts" / "replacement.json"
    transaction_id = "2" * 32
    assert _run_installer(first_source, install).returncode == 0
    replaced = _run_installer(
        second_source,
        install,
        "-ReplaceExistingVerifiedPortable",
        "-ReplacementTransactionId",
        transaction_id,
        "-ReplacementReceiptPath",
        str(receipt),
    )
    assert replaced.returncode == 0, replaced.stderr or replaced.stdout
    receipt_sha256 = hashlib.sha256(receipt.read_bytes()).hexdigest()
    receipt_before = receipt.read_bytes()
    evidence = tmp_path / "evidence" / "restore.json"

    restored = _run_restore(
        install,
        receipt,
        receipt_sha256,
        transaction_id,
        evidence,
    )

    assert restored.returncode == 0, restored.stderr or restored.stdout
    assert "replacement_restore_status=RESTORED" in restored.stdout
    assert receipt.read_bytes() == receipt_before
    assert (install / "app" / "main.py").read_text(encoding="utf-8") == (
        "# first portable main\n"
    )
    failed_root = install.parent / f".current.failed.{transaction_id}"
    assert (failed_root / "app" / "main.py").read_text(encoding="utf-8") == (
        "# second portable main\n"
    )
    assert not list(install.parent.glob(".current.rollback.*"))
    restored_evidence = json.loads(evidence.read_text(encoding="utf-8"))
    assert restored_evidence["status"] == "PASS"
    assert restored_evidence["prior_code_exact"] is True
    assert restored_evidence["failed_new_preserved"] is True

    repeated = _run_restore(
        install,
        receipt,
        receipt_sha256,
        transaction_id,
        tmp_path / "evidence" / "restore-repeat.json",
    )
    assert repeated.returncode == 0, repeated.stderr or repeated.stdout
    assert "replacement_restore_status=ALREADY_RESTORED" in repeated.stdout


def test_bootstrap_restore_failure_is_explicit_and_contains_pre_restore_state(tmp_path):
    first_source = _portable_release_fixture(
        tmp_path,
        directory="portable first",
        source_commit="a" * 40,
        main_payload="# first portable main\n",
    )
    second_source = _portable_release_fixture(
        tmp_path,
        directory="portable second",
        source_commit="b" * 40,
        main_payload="# second portable main\n",
    )
    install = tmp_path / "apps" / "current"
    receipt = tmp_path / "receipts" / "replacement.json"
    transaction_id = "3" * 32
    assert _run_installer(first_source, install).returncode == 0
    replaced = _run_installer(
        second_source,
        install,
        "-ReplaceExistingVerifiedPortable",
        "-ReplacementTransactionId",
        transaction_id,
        "-ReplacementReceiptPath",
        str(receipt),
    )
    assert replaced.returncode == 0, replaced.stderr or replaced.stdout
    receipt_sha256 = hashlib.sha256(receipt.read_bytes()).hexdigest()
    failure_evidence = tmp_path / "evidence" / "restore-failed.json"

    failed = _run_restore(
        install,
        receipt,
        receipt_sha256,
        transaction_id,
        failure_evidence,
        "-InjectRestoreFailureAfterDisplaceForTest",
    )

    assert failed.returncode != 0
    assert "replacement_restore_status=ROLLBACK_FAILED" in failed.stdout
    assert json.loads(failure_evidence.read_text(encoding="utf-8"))["status"] == (
        "ROLLBACK_FAILED"
    )
    assert (install / "app" / "main.py").read_text(encoding="utf-8") == (
        "# second portable main\n"
    )
    rollback = install.parent / f".current.rollback.{transaction_id}"
    assert (rollback / "app" / "main.py").read_text(encoding="utf-8") == (
        "# first portable main\n"
    )
    assert not (install.parent / f".current.failed.{transaction_id}").exists()


def test_bootstrap_refuses_verified_replacement_when_existing_tree_is_tampered(tmp_path):
    first_source = _portable_release_fixture(
        tmp_path,
        directory="portable first",
        source_commit="a" * 40,
        main_payload="# first portable main\n",
    )
    second_source = _portable_release_fixture(
        tmp_path,
        directory="portable second",
        source_commit="b" * 40,
        main_payload="# second portable main\n",
    )
    install = tmp_path / "apps" / "current"
    assert _run_installer(first_source, install).returncode == 0
    (install / "app" / "main.py").write_text("# tampered\n", encoding="utf-8")
    manifest_before = (install / "portable-manifest.json").read_bytes()
    receipt = tmp_path / "receipts" / "tampered-replacement.json"

    blocked = _run_installer(
        second_source,
        install,
        "-ReplaceExistingVerifiedPortable",
        "-ReplacementTransactionId",
        "4" * 32,
        "-ReplacementReceiptPath",
        str(receipt),
    )

    assert blocked.returncode != 0
    assert "integrity inventory differs" in (blocked.stderr + blocked.stdout)
    assert (install / "app" / "main.py").read_text(encoding="utf-8") == "# tampered\n"
    assert (install / "portable-manifest.json").read_bytes() == manifest_before
    assert not list(install.parent.glob(".current.rollback.*"))


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


def test_bootstrap_refuses_implicit_replacement_and_unfenced_inverse(tmp_path):
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
    assert removed.returncode != 0
    assert "requires exact attempt-bound writer fence parameters" in removed.stderr
    assert (install / "Container_Audit.exe").read_bytes() == b"container-audit-frozen-exe"
    assert user_state.read_bytes() == b"preserve-me"


def test_portable_product_forwards_explicit_server_base_url_only_to_onboarding():
    text = PORTABLE_INSTALLER.read_text(encoding="utf-8")
    parameter_index = text.index('[string]$ServerBaseUrl = "",')
    validation_index = text.index(
        "ServerBaseUrl must be a credential-free HTTPS origin without path, query, or fragment."
    )
    # The parameter is validated before the first helper is even defined, so an
    # invalid endpoint never reaches the manifest, fence or PlanOnly stages.
    assert parameter_index < validation_index < text.index("function Full(")
    assert validation_index < text.index("if ($PlanOnly) {")
    assert text.count("--server-base-url") == 1
    assert "Product $install '--onboard-current-user'" in text
    assert "Onboarding server endpoint readback failed" in text

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
foreach ($name in @('Arg','Product')) {
    $functions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { exit 11 }
    Invoke-Expression $functions[0].Extent.Text
}
$script:launches = @()
function Start-Process {
    param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru)
    $script:launches += [pscustomobject]@{
        FilePath = [string]$FilePath
        ArgumentList = [string]$ArgumentList
    }
    $process = [pscustomobject]@{ ExitCode = 0 }
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { }
    return $process
}
$root = 'C:\KMTech\Apps\Container_Audit\current'
$onboardingServerBaseUrl = 'https://qualification.example.invalid:8443'
Product $root '--onboard-current-user'
Product $root '--remove-current-user-setup'
$onboardingServerBaseUrl = ''
Product $root '--onboard-current-user'
Product $root '--remove-current-user-setup'
if ($script:launches.Count -ne 4) { exit 12 }
foreach ($launch in $script:launches) {
    if ($launch.FilePath -cne 'C:\KMTech\Apps\Container_Audit\current\runtime\pythonw.exe') { exit 13 }
}
$prefix = '-I -B C:\KMTech\Apps\Container_Audit\current\app\main.py '
$appRoot = ' --app-root C:\KMTech\Apps\Container_Audit\current\app'
$explicit = $prefix + '--onboard-current-user' + $appRoot + ' --server-base-url https://qualification.example.invalid:8443'
if ($script:launches[0].ArgumentList -cne $explicit) { Write-Output $script:launches[0].ArgumentList; exit 14 }
if ($script:launches[1].ArgumentList -cne ($prefix + '--remove-current-user-setup' + $appRoot)) { exit 15 }
if ($script:launches[2].ArgumentList -cne ($prefix + '--onboard-current-user' + $appRoot)) { exit 16 }
if ($script:launches[3].ArgumentList -cne ($prefix + '--remove-current-user-setup' + $appRoot)) { exit 17 }
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_portable_onboarding_endpoint_readback_fails_closed_on_foreign_or_missing_origin():
    text = PORTABLE_INSTALLER.read_text(encoding="utf-8")
    onboarding_index = text.index("Product $install '--onboard-current-user'")
    run_readback_index = text.index(
        "throw 'Onboarding Run readback failed.'", onboarding_index
    )
    endpoint_readback_index = text.index(
        "throw 'Onboarding server endpoint readback failed.'", run_readback_index
    )
    relay_pid_index = text.index(
        "throw 'Onboarding relay process id type/readback failed.'",
        endpoint_readback_index,
    )
    assert onboarding_index < run_readback_index < endpoint_readback_index < relay_pid_index

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
$candidates = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.StartsWith('if ($onboardingServerBaseUrl) {') -and
        $node.Extent.Text.Contains("throw 'Onboarding server endpoint readback failed.'")
}, $true))
if ($candidates.Count -ne 1) { exit 11 }
$readback = $candidates[0].Extent.Text
function Invoke-Readback([string]$Requested, $StateReadback) {
    $onboardingServerBaseUrl = $Requested
    $onboardingServerBaseUri = $null
    if ($Requested) { $onboardingServerBaseUri = [Uri]$Requested }
    $onboarding = [pscustomobject]@{ status = 'READY'; state_readback = $StateReadback }
    try { Invoke-Expression $readback; return 'ADMITTED' }
    catch { return [string]$_.Exception.Message }
}
$explicit = 'https://qualification.example.invalid:8443'
$expected = 'Onboarding server endpoint readback failed.'
if ((Invoke-Readback $explicit ([pscustomobject]@{ base_url = 'https://QUALIFICATION.example.invalid:8443' })) -cne 'ADMITTED') { exit 12 }
if ((Invoke-Readback 'https://qualification.example.invalid' ([pscustomobject]@{ base_url = 'https://qualification.example.invalid:443' })) -cne 'ADMITTED') { exit 13 }
if ((Invoke-Readback $explicit ([pscustomobject]@{ base_url = 'https://worker.kmtecherp.com' })) -cne $expected) { exit 14 }
if ((Invoke-Readback $explicit ([pscustomobject]@{ base_url = 'https://qualification.example.invalid' })) -cne $expected) { exit 15 }
if ((Invoke-Readback $explicit ([pscustomobject]@{ base_url = 'http://qualification.example.invalid:8443' })) -cne $expected) { exit 16 }
if ((Invoke-Readback $explicit ([pscustomobject]@{ status = 'READY' })) -cne $expected) { exit 17 }
if ((Invoke-Readback $explicit $null) -cne $expected) { exit 18 }
if ((Invoke-Readback '' ([pscustomobject]@{ base_url = 'https://worker.kmtecherp.com' })) -cne 'ADMITTED') { exit 19 }
if ((Invoke-Readback '' ([pscustomobject]@{ status = 'READY' })) -cne 'ADMITTED') { exit 20 }
exit 0
"""
    completed = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout


def _run_portable_plan(source: Path, install: Path, *extra: str):
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
            str(source / "INSTALL_CANONICAL_PORTABLE.ps1"),
            "-SourceRoot",
            str(source),
            "-InstallRoot",
            str(install),
            "-PlanOnly",
            "-AllowNoncanonicalLayoutForTest",
            "-SkipSignatureValidationForTest",
            *extra,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )


def test_portable_plan_reports_explicit_server_base_url_without_mutation(tmp_path):
    source = _portable_release_fixture(tmp_path)
    install = tmp_path / "apps" / "current"

    explicit = _run_portable_plan(
        source, install, "-ServerBaseUrl", "https://qualification.example.invalid:8443/"
    )
    omitted = _run_portable_plan(source, install)

    assert explicit.returncode == 0, explicit.stderr or explicit.stdout
    assert "install_status=PLAN_ONLY" in explicit.stdout
    assert "registry_changed=false" in explicit.stdout
    assert (
        _output_value(explicit.stdout, "onboarding_server_base_url")
        == "https://qualification.example.invalid:8443"
    )
    assert omitted.returncode == 0, omitted.stderr or omitted.stdout
    assert _output_value(omitted.stdout, "onboarding_server_base_url") == "PRODUCT_DEFAULT"
    assert not install.exists()


@pytest.mark.parametrize(
    "server_base_url",
    [
        "http://qualification.example.invalid",
        "https://operator:secret@qualification.example.invalid",
        "https://qualification.example.invalid/api/producer-ingest/v1/source-file",
        "https://qualification.example.invalid?plane=shadow",
        "https://qualification.example.invalid#fragment",
        "https://localhost:8443",
        "https://127.0.0.1:8443",
        "https://[::1]:8443",
        "https://qualification.example.invalid:70000",
        "qualification.example.invalid:8443",
        "https://qualification example.invalid",
        r"https://qualification.example.invalid\api",
    ],
)
def test_portable_installer_rejects_invalid_server_base_url_before_plan_output(
    tmp_path, server_base_url
):
    source = _portable_release_fixture(tmp_path)
    install = tmp_path / "apps" / "current"

    completed = _run_portable_plan(source, install, "-ServerBaseUrl", server_base_url)

    assert completed.returncode != 0
    diagnostic = "".join((completed.stderr + completed.stdout).split()).lower()
    assert "serverbaseurlmustbeacredential-freehttpsorigin" in diagnostic
    assert "install_status=" not in completed.stdout
    assert not install.exists()

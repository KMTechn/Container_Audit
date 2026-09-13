"""CA's original Manifest contracts and the pre-execution shared pin boundary."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

import pytest

from tests.powershell_contracts import run_functions, run_powershell
from tests.test_zero_touch_installer import ROOT, PORTABLE_INSTALLER, _portable_release_fixture


ENGINES = ("powershell.exe", "pwsh.exe")
REQUIRED = (
    "portable-manifest.json", "runtime/python.exe", "runtime/pythonw.exe", "app/main.py",
    "launch-container-audit.cmd", "INSTALL_CANONICAL_PORTABLE.ps1", "INSTALL_THIS_PC.ps1",
    "tools/bootstrap_integrity.ps1", "tools/container_writer_fence.ps1",
    "tools/container_writer_session.ps1", "tools/container_writer_session_contract.json",
    "tools/container_writer_sink_inventory.json",
)


@pytest.mark.parametrize("engine", ENGINES)
def test_canonical_entrypoint_authenticates_bootstrap_before_loading_it(tmp_path, engine):
    assert shutil.which(engine), f"Required parity engine is unavailable: {engine}"
    root = _portable_release_fixture(tmp_path)
    marker = tmp_path / "bootstrap-executed"
    environment = dict(os.environ, KMTECH_FACTORY_INSTALL_TEST_MODE="1", CA_POISON_MARKER=str(marker))
    arguments = [engine, "-NoProfile", "-NonInteractive", "-File",
                 str(root / "INSTALL_CANONICAL_PORTABLE.ps1"), "-SourceRoot", str(root),
                 "-InstallRoot", str(tmp_path / "current"), "-PlanOnly",
                 "-AllowNoncanonicalLayoutForTest", "-SkipSignatureValidationForTest"]
    admitted = run_powershell(arguments, env=environment, timeout=30)
    assert admitted.returncode == 0, admitted.stdout + admitted.stderr
    assert "install_status=PLAN_ONLY" in admitted.stdout
    with (root / "tools/bootstrap_integrity.ps1").open("a", encoding="utf-8") as stream:
        stream.write("\n[IO.File]::WriteAllText($env:CA_POISON_MARKER,'executed')\n")
    rejected = run_powershell(arguments, env=environment, timeout=30)
    assert rejected.returncode != 0
    assert "Bootstrap integrity helper pin mismatch." in rejected.stderr
    assert not marker.exists()
    assert not (tmp_path / "current").exists()


@pytest.mark.parametrize("engine", ENGINES)
def test_original_ca_manifest_and_wrapper_parity(tmp_path, engine):
    assert shutil.which(engine), f"Required parity engine is unavailable: {engine}"
    baseline = tmp_path / "before.ps1"
    shutil.copyfile(ROOT / "tests/fixtures/ca_portable_functions_before_x13b.ps1", baseline)
    cases = []

    def packet(name, *, signature="valid", unsigned=True, error=""):
        root = _portable_release_fixture(tmp_path, directory=name)
        cases.append(dict(root=str(root), signature=signature, unsigned=unsigned, error=error))
        return root

    packet("normal bypass")
    packet("valid signature", unsigned=False)
    root = packet("signed CPython", signature="native", unsigned=False)
    for name in ("python.exe", "pythonw.exe"):
        shutil.copyfile(Path(sys.executable).with_name(name), root / "runtime" / name)
    manifest_path = root / "portable-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["runtime_pythonw_sha256"] = hashlib.sha256((root / "runtime/pythonw.exe").read_bytes()).hexdigest()
    manifest["byte_count_before_manifest"] = sum(
        path.stat().st_size for path in root.rglob("*") if path.is_file() and path != manifest_path
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    packet("unsigned native", signature="native", unsigned=False,
           error="Signed CPython readback failed: runtime\\python.exe")
    packet("second signature", signature="second", unsigned=False,
           error="Signed CPython readback failed: runtime\\pythonw.exe")
    for index, relative in enumerate(REQUIRED):
        root = packet(f"missing-{index}", error="Portable tree is missing " + relative.replace("/", "\\") + ".")
        (root / relative).unlink()
    for name, contents, error in (
        ("oversized", b" " * 65537, "Portable manifest is oversized."),
        ("invalid json", b"{", ""),
    ):
        root = packet(name, error=error or "JSON")
        (root / "portable-manifest.json").write_bytes(contents)
    for field, value, error in (
        ("schema", "foreign", "Portable manifest readback failed."),
        ("writer_fence_helper_path", "wrong", "Portable manifest readback failed."),
        ("runtime_pythonw_sha256", "0" * 64, "Portable manifest readback failed."),
        ("file_count_before_manifest", "12", "Portable tree metrics differ from the manifest."),
        ("byte_count_before_manifest", -1, "Portable tree metrics differ from the manifest."),
    ):
        root = packet(field, unsigned=False, error=error)
        path = root / "portable-manifest.json"
        record = json.loads(path.read_bytes())
        record[field] = value
        path.write_text(json.dumps(record), encoding="utf-8")
    root = packet("junction", error="Portable tree contains a reparse point:")
    cases[-1]["junction"] = True
    # Both defects: preserve required-file rejection before bounded parsing.
    root = packet("ordered defects", error="Portable tree is missing runtime\\python.exe.")
    (root / "runtime/python.exe").unlink()
    (root / "portable-manifest.json").write_bytes(b" " * 65537)
    case_path = tmp_path / "cases.json"
    case_path.write_text(json.dumps(cases), encoding="utf-8")
    names = ["Full", "Sha", "Same", "Manifest", "Test-JsonInteger", "Test-JsonTrue",
             "Get-WriterContractSessionMutexName", "Assert-WriterSessionPublicContract",
             "Assert-WriterSinkInventory"]
    result = run_functions(tmp_path, PORTABLE_INSTALLER, names, r'''
$tokens=$null; $errors=$null
$before=[Management.Automation.Language.Parser]::ParseFile($env:CA_BEFORE,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'baseline parse failed' }
function Observe($Case, [bool]$Original) {
    if ($Original) {
        foreach ($definition in $before.EndBlock.Statements) {
            if ($definition -is [Management.Automation.Language.FunctionDefinitionAst]) {
                Invoke-Expression $definition.Extent.Text
            }
        }
    }
    $script:signatureCalls=@()
    if ($Case.signature -cne 'native') {
        function Get-AuthenticodeSignature([string]$Path) {
            $relative=Split-Path -Leaf $Path
            $script:signatureCalls += $relative
            $status=if ($Case.signature -ceq 'second' -and $relative -ceq 'pythonw.exe') { 'NotSigned' } else { 'Valid' }
            return [pscustomobject]@{Status=$status}
        }
    }
    try {
        $value=Manifest $Case.root ([bool]$Case.unsigned)
        return [pscustomobject]@{ok=$true; value=($value | ConvertTo-Json -Depth 20 -Compress); calls=@($script:signatureCalls)}
    }
    catch {
        return [pscustomobject]@{ok=$false; type=$_.Exception.GetType().FullName; error=$_.Exception.Message; calls=@($script:signatureCalls)}
    }
}
$count=0
foreach ($case in (Get-Content -LiteralPath $env:CA_CASES -Raw | ConvertFrom-Json)) {
    if ($case.junction) {
        $target=Join-Path $env:CA_CONTRACT_ROOT 'junction-target'
        New-Item -ItemType Directory -Path $target | Out-Null
        New-Item -ItemType Junction -Path (Join-Path $case.root 'linked') -Target $target | Out-Null
    }
    $expected=Observe $case $true
    $actual=Observe $case $false
    if (($expected | ConvertTo-Json -Depth 20 -Compress) -cne ($actual | ConvertTo-Json -Depth 20 -Compress)) {
        throw ('Manifest parity differs: '+$case.root+' '+($expected | ConvertTo-Json -Compress)+' '+($actual | ConvertTo-Json -Compress))
    }
    if ($case.error) {
        if ($actual.ok) { throw ('rejection was lost: '+$case.root) }
        if ($case.error -cne 'JSON' -and -not $actual.error.Contains($case.error)) { throw ('wrong rejection: '+$actual.error) }
        if ($case.signature -cne 'native' -and -not $case.error.StartsWith('Signed CPython') -and $actual.calls.Count) {
            throw 'signature ran before schema/hash/metrics validation'
        }
    }
    elseif (-not $actual.ok) { throw $actual.error }
    elseif ($case.unsigned -and $actual.calls.Count) { throw 'unsigned bypass queried signatures' }
    elseif (-not $case.unsigned -and $case.signature -cne 'native' -and ($actual.calls -join ',') -cne 'python.exe,pythonw.exe') { throw 'signature order differs' }
    $count++
}
# Original parameter binding, known SHA and native error behavior are observable.
$shaPath=Join-Path $env:CA_CONTRACT_ROOT 'sha 한글.bin'
[IO.File]::WriteAllBytes($shaPath,[byte[]](97,98,99))
if ((Sha $shaPath) -cne 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') { throw 'known SHA differs' }
$handle=[IO.File]::Open($shaPath,'Open','ReadWrite','None'); $handle.Dispose()
foreach ($name in @('Full','Sha')) {
    $original=@($before.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))[0]
    $after=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))[0]
    if (($original.Parameters.Extent.Text -join ',') -cne ($after.Parameters.Extent.Text -join ',')) { throw 'wrapper binding changed' }
    $inputs=if ($name -ceq 'Sha') { @($shaPath,(Join-Path $env:CA_CONTRACT_ROOT 'absent'),'') } else {
        @($env:CA_CONTRACT_ROOT,($env:CA_CONTRACT_ROOT+'\a\..\b\'),'relative','\\?\C:\x','C:\','',$null)
    }
    foreach ($inputValue in $inputs) {
        $values=@()
        foreach ($originalMode in @($true,$false)) {
            $values += & {
                if ($originalMode) { Invoke-Expression $original.Extent.Text }
                try {
                    $value=if ($name -ceq 'Sha') { Sha $inputValue } else { Full $inputValue 'purpose' }
                    'OK:'+[string]$value
                } catch { $_.Exception.GetType().FullName+':'+$_.Exception.Message }
            }
        }
        if ($values[0] -cne $values[1]) { throw ('wrapper parity differs: '+$name+' '+($values -join ';')) }
        $count++
    }
}
Write-Output ('PASS CA parity cases='+$count+' engine='+$PSVersionTable.PSVersion)
''', values={"CA_BEFORE": str(baseline), "CA_CASES": str(case_path)}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS CA parity cases=36" in result.stdout


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("shape", ("wrapped", "nested", "empty", "nested-empty"))
def test_shared_manifest_rejects_array_wrapped_json(tmp_path, engine, shape):
    """Upstream 0.3.0 regression: the caller must retain the original rejection."""
    assert shutil.which(engine), f"Required parity engine is unavailable: {engine}"
    root = _portable_release_fixture(tmp_path)
    path = root / "portable-manifest.json"
    if shape in ("empty", "nested-empty"):
        contents = b"[]" if shape == "empty" else b"[[]]"
    else:
        depth = (1 if engine == "powershell.exe" else 2) if shape == "wrapped" else 3
        contents = b"[" * depth + path.read_bytes() + b"]" * depth
    path.write_bytes(contents)
    baseline = tmp_path / "before.ps1"
    shutil.copyfile(ROOT / "tests/fixtures/ca_portable_functions_before_x13b.ps1", baseline)
    names = ["Full", "Sha", "Same", "Manifest", "Test-JsonInteger", "Test-JsonTrue",
             "Get-WriterContractSessionMutexName", "Assert-WriterSessionPublicContract",
             "Assert-WriterSinkInventory"]
    result = run_functions(tmp_path, PORTABLE_INSTALLER, names, r'''
$originalError = & {
    . $env:CA_BEFORE
    try { [void](Manifest $env:CA_PACKET $true); return '' }
    catch { return $_.Exception.Message }
}
$currentError = try { [void](Manifest $env:CA_PACKET $true); '' } catch { $_.Exception.Message }
[pscustomobject]@{original_error=$originalError; current_error=$currentError; engine=[string]$PSVersionTable.PSVersion} | ConvertTo-Json -Compress
''', values={"CA_BEFORE": str(baseline), "CA_PACKET": str(root)}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["original_error"] == "Portable manifest readback failed.", observed
    assert observed["current_error"] == observed["original_error"], observed


@pytest.mark.parametrize("engine", ENGINES)
def test_bootstrap_pins_leaf_before_execution_in_source_and_portable_trees(tmp_path, engine):
    assert shutil.which(engine), f"Required parity engine is unavailable: {engine}"
    cases = []
    for mode in ("source", "portable"):
        for mutation in ("valid", "leaf", "manifest", "lock", "rehashed", "missing", "junction", "ancestor"):
            root = tmp_path / f"{mode}-{mutation}"
            app = root / "app" if mode == "portable" else root
            shutil.copytree(ROOT / "kmtech_shared", app / "kmtech_shared",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            for name in ("kmtech_shared.manifest.json", "kmtech_shared.lock.json"):
                shutil.copyfile(ROOT / name, app / name)
            leaf = app / "kmtech_shared/powershell/portable.ps1"
            if mutation in ("leaf", "rehashed"):
                leaf.write_text("[IO.File]::WriteAllText($env:CA_POISON_MARKER,'executed')", encoding="utf-8")
            if mutation == "manifest":
                with (app / "kmtech_shared.manifest.json").open("ab") as stream:
                    stream.write(b"\n")
            if mutation in ("lock", "rehashed"):
                manifest = app / "kmtech_shared.manifest.json"
                if mutation == "rehashed":
                    record = json.loads(manifest.read_bytes())
                    record["files"]["kmtech_shared/powershell/portable.ps1"] = hashlib.sha256(leaf.read_bytes()).hexdigest()
                    manifest.write_text(json.dumps(record), encoding="utf-8")
                lock = json.loads((app / "kmtech_shared.lock.json").read_bytes())
                lock["manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest() if mutation == "rehashed" else "0" * 64
                (app / "kmtech_shared.lock.json").write_text(json.dumps(lock), encoding="utf-8")
            if mutation == "missing":
                leaf.unlink()
            cases.append(dict(root=str(root), app=str(app), mutation=mutation))
    case_path = tmp_path / "bootstrap-cases.json"
    case_path.write_text(json.dumps(cases), encoding="utf-8")
    marker = tmp_path / "poison-marker"
    result = run_functions(tmp_path, ROOT / "tools/bootstrap_integrity.ps1",
                           ["Get-StrictFullPath", "Get-FileSha256", "Assert-BootstrapNoReparsePoint",
                            "Get-BootstrapSharedPortableLeaf"], r'''
$count=0
foreach ($case in (Get-Content -LiteralPath $env:CA_CASES -Raw | ConvertFrom-Json)) {
    if ($case.mutation -ceq 'junction') {
        $shared=Join-Path $case.app 'kmtech_shared'
        $target=$shared+'-original'
        foreach ($path in @($shared,$target)) {
            if (-not [IO.Path]::GetFullPath($path).StartsWith($env:CA_CONTRACT_ROOT+'\',[StringComparison]::OrdinalIgnoreCase)) {
                throw 'junction fixture escaped its owned root'
            }
        }
        if (Test-Path -LiteralPath $target) { throw 'junction original already exists' }
        Move-Item -LiteralPath $shared -Destination $target
        New-Item -ItemType Junction -Path $shared -Target $target | Out-Null
    }
    if ($case.mutation -ceq 'ancestor') {
        $link=$case.root+'-linked'
        New-Item -ItemType Junction -Path $link -Target $case.root | Out-Null
        $case.root=$link
    }
    $errorText=''
    try {
        $leaf=Get-BootstrapSharedPortableLeaf $case.root
        . $leaf
        if ($leaf -cne (Join-Path $case.app 'kmtech_shared\powershell\portable.ps1')) { throw 'wrong app root' }
        if (-not (Get-Command Get-KmtechFileSha -ErrorAction SilentlyContinue)) { throw 'leaf did not load' }
    } catch { $errorText=$_.Exception.Message }
    if (Test-Path -LiteralPath $env:CA_POISON_MARKER) { throw 'untrusted shared code executed' }
    if ($case.mutation -ceq 'valid') {
        if ($errorText) { throw $errorText }
    }
    else {
        $expected=switch ($case.mutation) {
            'leaf' { 'Shared PowerShell leaf pin mismatch.' }
            'manifest' { 'Shared manifest pin mismatch.' }
            'lock' { 'Shared consumer lock pin mismatch.' }
            'rehashed' { 'Shared consumer lock pin mismatch.' }
            'missing' { 'shared installer input is unavailable.' }
            default { 'contains a reparse point:' }
        }
        if (-not $errorText.Contains($expected)) { throw ('wrong bootstrap rejection: '+$case.mutation+' '+$errorText) }
    }
    $count++
}
Write-Output ('PASS bootstrap cases='+$count+' engine='+$PSVersionTable.PSVersion)
''', values={"CA_CASES": str(case_path), "CA_POISON_MARKER": str(marker)}, engine=engine)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS bootstrap cases=16" in result.stdout
    assert not marker.exists()

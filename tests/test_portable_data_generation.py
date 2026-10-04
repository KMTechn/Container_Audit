"""A stock Python packet must verify its code entrypoint without a frozen EXE."""
import json
from pathlib import Path


def test_python_packet_generation_identity(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    from tests.powershell_contracts import run_functions

    source_root = Path(onboarding.__file__).resolve().parent
    packet = tmp_path / "packet"
    app = packet / "app"
    app.mkdir(parents=True)
    (app / "Container_Audit.py").write_text('CURRENT_VERSION = "v2.0.99"\n')
    (app / "data_generation_guard.py").write_text("# copied runtime code\n")
    (packet / "portable-manifest.json").write_text(json.dumps({
        "version": "v2.0.99", "source_commit": "a" * 40}))
    literal = str(packet).replace("'", "''")
    result = run_functions(tmp_path, source_root / "tools/bootstrap_integrity.ps1",
        ["Get-StrictFullPath", "Get-RelativeCodePath", "Get-FileSha256", "Get-CodeInventory",
         "Get-InventoryAggregate", "Write-Utf8Json", "Write-BootstrapIntegrityRecord"], f"""
$BootstrapIntegritySchema='container-audit-bootstrap-integrity-v1'
$BootstrapIntegrityFileName='bootstrap-integrity.json'
[void](Write-BootstrapIntegrityRecord -Root '{literal}' -CodeRootIdentity '.')
""")
    assert result.returncode == 0, result.stdout + result.stderr
    monkeypatch.setattr(guard, "__file__", str(app / "data_generation_guard.py"))
    assert guard._runtime_release() == {"version": "v2.0.99", "build_id": "a" * 40,
        "data_compatible_min_version": "v2.0.99", "compatibility_verified": False}
def test_stock_application_contains_data_generation_adapter(tmp_path):
    from tools import build_portable_release_candidate as builder

    source = Path(builder.__file__).resolve().parents[1]
    target = tmp_path / "copied-app"
    builder._copy_application(source, target)
    assert (target / "data_generation_guard.py").read_bytes() == (source / "data_generation_guard.py").read_bytes()
    assert (target / "tools/check_release_version.py").is_file()
    assert (target / "kmtech_shared/powershell/data_generation.ps1").is_file()

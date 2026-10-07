"""Fresh writer-session contexts must reach both bounded manifest consumers."""
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tests/writer_session_shared_portable_probe.ps1"


def _probe(engine, code_root, fixture_root, case):
    child = run_powershell(
        [engine, "-NoProfile", "-NonInteractive", "-File", str(PROBE),
         "-CodeRoot", str(code_root), "-FixtureRoot", str(fixture_root), "-Case", case],
        cwd=ROOT,
    )
    assert child.returncode == 0, child.stdout + child.stderr
    return json.loads(child.stdout.splitlines()[-1])


def _identity_fixture(root):
    producer = root / "producer"
    (producer / "tools").mkdir(parents=True)
    canonical = producer / "INSTALL_CANONICAL_PORTABLE.ps1"
    shutil.copyfile(ROOT / canonical.name, canonical)
    shutil.copyfile(ROOT / "tools/bootstrap_integrity.ps1", producer / "tools/bootstrap_integrity.ps1")
    (producer / "portable-manifest.json").write_text(json.dumps({
        "installer_sha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    control = root / "install/update-control"
    control.mkdir(parents=True)
    (root / "install/current").mkdir()
    (control / "policy.json").write_text(json.dumps({"operator_sid": "S-1-5-21-1-2-3-1001"}), encoding="utf-8")
    (control / "active.json").write_text(json.dumps({
        "schema": "container-audit-startup-update-v1", "sha": "a" * 40,
    }), encoding="utf-8")
    bundle = root / "install/versions" / ("a" * 40)
    (bundle / "runtime").mkdir(parents=True)
    (bundle / "app").mkdir()
    (bundle / "runtime/pythonw.exe").write_bytes(b"")
    (bundle / "app/main.py").write_bytes(b"")
    (bundle / "portable-manifest.json").write_text(json.dumps({
        "source_commit": "a" * 40, "startup_update_protocol": 1, "relay_identity_protocol": 1,
    }), encoding="utf-8")
    (bundle / "bootstrap-integrity.json").write_text(json.dumps({"code_root": "."}), encoding="utf-8")


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("normal", "managed"))
def test_fresh_writer_session_reaches_actual_manifest_consumers(tmp_path, engine, case):
    _identity_fixture(tmp_path)
    record = _probe(engine, ROOT, tmp_path, case)
    assert record["status"] == "PASS", record
    assert not record["reader_loaded"] and not record["missing_reader"], record
    assert record["bootstrap_sha256"] == hashlib.sha256((ROOT / "tools/bootstrap_integrity.ps1").read_bytes()).hexdigest()
    assert record["loader_count"] == 2
    assert record["native_api_compiled"] if case == "normal" else record["managed_identity_verified"]
    assert record["host_dispatch_attempted"] is False


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("case", ("normal", "managed"))
@pytest.mark.parametrize("drift", ("oversized", "malformed", "binding"))
def test_actual_writer_manifest_consumers_reject_invalid_input(tmp_path, engine, case, drift):
    _identity_fixture(tmp_path)
    manifest = (tmp_path / "producer/portable-manifest.json" if case == "normal" else
                tmp_path / "install/versions" / ("a" * 40) / "portable-manifest.json")
    if drift == "oversized":
        manifest.write_bytes(b" " * 65537)
    elif drift == "malformed":
        manifest.write_text("{", encoding="utf-8")
    else:
        value = json.loads(manifest.read_text(encoding="utf-8"))
        value["installer_sha256" if case == "normal" else "source_commit"] = "invalid"
        manifest.write_text(json.dumps(value), encoding="utf-8")
    record = _probe(engine, ROOT, tmp_path, case)
    assert record["status"] == "RED" and record["reject_code"] == {
        "oversized": "MANIFEST_OVERSIZED", "malformed": "MANIFEST_JSON_INVALID",
        "binding": "MANIFEST_BINDING_DIFFERS",
    }[drift], record
    assert not record["missing_reader"] and not record["reader_loaded"], record
    assert record["location_module"] == "bootstrap_integrity.ps1" and record["location_line"] > 0
    assert record["bootstrap_sha256"] == hashlib.sha256((ROOT / "tools/bootstrap_integrity.ps1").read_bytes()).hexdigest()
    assert record["host_dispatch_attempted"] is False
    assert record["native_api_compiled"] is False and record["managed_identity_verified"] is False

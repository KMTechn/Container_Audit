"""PowerShell 5/7 atomic publication; native file sharing only, no real directories/windows."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENGINES = ["C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", shutil.which("pwsh")]


@pytest.mark.parametrize("engine", ENGINES, ids=["PS5", "PS7"])
def test_ps_overlap_persistent_original_error_and_publication_modes(tmp_path, engine):
    assert engine and Path(engine).is_file()
    receipt = tmp_path / "receipt.json"
    with (tmp_path / "stdout-private.log").open("wb") as out, (tmp_path / "stderr-private.log").open("wb") as err:
        result = subprocess.run([engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(ROOT / "tests/ca_atomic_replace_probe.ps1"), str(ROOT / "tools/bootstrap_integrity.ps1"),
            str(tmp_path), str(receipt)], stdout=out, stderr=err, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0
    rows = {row["case"]: row for row in json.loads(receipt.read_bytes())}
    for mode in ("Replace", "WriteThrough"):
        overlap = rows["overlap-" + mode]
        assert overlap["attempts"] >= 2 and overlap["first_present"] and overlap["value"] == "new"
        persistent = rows["persistent-" + mode]
        assert persistent["attempts"] >= 2 and 1.4 <= persistent["seconds"] < 2
        assert persistent["original"] and persistent["source_preserved"] and persistent["value"] == "old"
    assert rows["missing"]["attempts"] == 1 and rows["missing"]["original"]
    assert rows["create-collision"] == {"case": "create-collision", "attempts": 1, "failed": True, "value": "old", "source_preserved": True}
    assert rows["backup"] == {"case": "backup", "attempts": 1, "value": "new", "backup": "old"}


@pytest.mark.parametrize("engine", ENGINES, ids=["PS5", "PS7"])
def test_fence_cold_load_pins_bytes_and_preserves_verified_in_memory_library(tmp_path, engine):
    assert engine and Path(engine).is_file()
    receipt = tmp_path / "load.json"
    with (tmp_path / "stdout-private.log").open("wb") as out, (tmp_path / "stderr-private.log").open("wb") as err:
        result = subprocess.run([engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(ROOT / "tests/ca_atomic_fence_load_probe.ps1"), str(ROOT / "tools/container_writer_fence.ps1"),
            str(ROOT / "tools/bootstrap_integrity.ps1"), str(tmp_path), str(receipt)], stdout=out, stderr=err, timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0
    assert json.loads(receipt.read_bytes()) == {"cold": True, "cached": True, "rejected": True}

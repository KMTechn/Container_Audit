"""PS 5.1/7 execute the real three installer manifest readers headlessly."""
import shutil

import pytest

from tests.powershell_contracts import run_powershell
from tests.test_zero_touch_installer import ROOT, _portable_release_fixture


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_installers_accept_only_none_or_the_three_pinned_unsigned_natives(tmp_path, engine):
    assert shutil.which(engine), "required PowerShell engine missing"
    portable = _portable_release_fixture(tmp_path)
    result = run_powershell([engine, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                             str(ROOT / "tests/portable_unsigned_pe.ps1"),
                             "-SourceRoot", str(ROOT), "-PortableRoot", str(portable)], timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "UNSIGNED_NATIVE_CONTRACT_PASS" in result.stdout

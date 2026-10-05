"""Sub-291 final-output probe port: actual CA catch/finally, synthetic secrets only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('engine', ('powershell.exe', 'pwsh.exe'))
@pytest.mark.parametrize('case', ('failure', 'rollback', 'rollback_failure'))
def test_final_exception_and_console_are_redacted_without_losing_original(tmp_path, engine, case):
    output = tmp_path / 'counts.json'
    environment = dict(os.environ, TEMP=str(tmp_path), TMP=str(tmp_path))
    process = subprocess.run([
        shutil.which(engine), '-NoProfile', '-NonInteractive', '-File',
        str(ROOT / 'tests/canonical_final_sink_probe.ps1'),
        str(ROOT / 'INSTALL_CANONICAL_PORTABLE.ps1'), str(output), sys.executable,
        str(ROOT / 'tests/canonical_rollback_generation_child.py'), str(tmp_path / 'sandbox'), case,
    ], env=environment, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=90)
    if process.returncode or not output.is_file():
        pytest.fail('Isolated final sink probe failed to produce counts', pytrace=False)
    result = json.loads(output.read_bytes())
    assert result['real_product_catch_and_finally'] and result['native_host_calls'] == 0
    assert result['failed']
    assert result['console_raw_hits'] == result['exception_raw_hits'] == 0
    assert result['original_object_preserved'] and result['inner_chain_preserved']

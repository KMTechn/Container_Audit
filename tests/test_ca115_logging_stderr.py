"""Writer proof refusals remain silent without application logging setup."""
import os
from pathlib import Path
import subprocess
import sys

def test_proof_refusal_without_logging_configuration_has_empty_stderr():
    code = """
import logging
from pathlib import Path
import writer_session_fence as fence
logging.getLogger().handlers.clear()
def fail(*args):
    raise OSError("private diagnostic must not escape")
fence._acquire_named_mutex = fail
scope = fence._FailedInstallerRemoval(Path.cwd(), Path.cwd())
assert not scope.admits("current_user_setup_removal", Path.cwd(), {
    "status": "INSTALLING", "owner_kind": "canonical_installer",
    "session_authority_mutex_name": "unused-test-authority"})
"""
    result = subprocess.run([sys.executable, "-B", "-c", code],
        cwd=Path(__file__).resolve().parents[1], capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    assert result.returncode == 0, "proof refusal subprocess failed"
    assert result.stderr == b"", "proof refusal wrote an uncontracted stderr line"

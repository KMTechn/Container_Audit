from pathlib import Path
import json
import os
import subprocess
import sys

import pytest

SCENARIOS = ("prepared_locator", "prepared_secret", "prepared_tls", "raw_locator",
             "gui_pin_secret", "profile_owner", "protected_admin_owner",
             "pin_deferred_tls", "runtime_deferred_tls", "transfer_deferred_tls",
             "registration_tls", "installer_tls")

@pytest.mark.parametrize("scenario", SCENARIOS)
def test_owner_upgrade_after_startup_refuses_first_security_read(tmp_path, scenario):
    result = tmp_path / "result.json"
    child = Path(__file__).with_name("security_input_first_read_child.py")
    completed = subprocess.run([sys.executable, "-B", str(child), str(child.parent.parent),
        str(tmp_path / "isolated"), scenario, str(result)], capture_output=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=90)
    (tmp_path / "child.stdout.txt").write_bytes(completed.stdout)
    (tmp_path / "child.stderr.txt").write_bytes(completed.stderr)
    assert completed.returncode == 0, "isolated child failed; output is preserved privately"
    observed = json.loads(result.read_text(encoding="utf-8"))
    assert observed["startup_allowed"] is True
    assert observed["native_g"] is True
    assert observed["status"] == "REFUSE"
    assert all(observed[name] == 0 for name in
               ("locator_reads", "secret_reads", "tls_reads", "decryptions", "requests"))

def test_same_owner_generation_retains_credential_read_and_decrypt(tmp_path):
    result = tmp_path / "result.json"
    child = Path(__file__).with_name("security_input_first_read_child.py")
    completed = subprocess.run([sys.executable, "-B", str(child), str(child.parent.parent),
        str(tmp_path / "isolated"), "allowed", str(result)], capture_output=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=90)
    (tmp_path / "child.stdout.txt").write_bytes(completed.stdout)
    (tmp_path / "child.stderr.txt").write_bytes(completed.stderr)
    assert completed.returncode == 0
    observed = json.loads(result.read_text(encoding="utf-8"))
    assert observed["startup_allowed"] is True
    assert observed["status"] == "ALLOWED"
    assert observed["locator_reads"] == 0
    assert observed["secret_reads"] == observed["decryptions"] == 1

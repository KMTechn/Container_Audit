"""Copy the coordinator's approved input into the owned test directory."""
import hashlib
from pathlib import Path

CANONICAL_SETTINGS = Path(
    "D:/KMTech/program-improvement-20260912/work/program/w9mgrweb/field-update-feed-1015/"
    "container_audit.auto-update-settings.json"
)
CANONICAL_SHA256 = "1b9372bd13d7b7ffc1d5e155cc1a984f12bea47453e1be0c9252e30ed3de5359"


def canonical_release_settings(tmp_path):
    assert CANONICAL_SETTINGS.stat().st_size == 219
    raw = CANONICAL_SETTINGS.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CANONICAL_SHA256
    path = tmp_path / "canonical-auto-update-settings.json"
    path.write_bytes(raw)
    return path

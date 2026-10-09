"""Keep sanitized UNKNOWN evidence private through the existing CA guard."""
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from data_generation_guard import DataGenerationBlocked
from kmtech_shared import data_generation as generation
from tests.test_container_writer_sink_inventory import _load_module, _write_minimal_inventory_fixture


@pytest.mark.parametrize("failure", ["malformed", "denied"])
def test_unknown_cause_survives_guard_without_changing_public_decision(tmp_path, monkeypatch, failure):
    marker = tmp_path / "data-generation.json"
    marker.write_bytes(b"{invalid")
    if failure == "denied":
        def denied(*args):
            raise PermissionError("synthetic private detail")
        monkeypatch.setattr(generation, "_read", denied)
    decision = generation.probe_downgrade([marker], "v2.0.99", app_id="container_audit",
        subject_sid="S-1-5-21-111", target_build_id="a" * 40)
    assert decision["status"] == "UNKNOWN" and not decision["allowed"]
    cause = decision.private_cause
    assert cause is not None
    assert cause["type"] == ("PermissionError" if failure == "denied" else "JSONDecodeError")
    assert set(cause) == {"type", "type_module", "raised_at", "seen_in"}
    blocked = DataGenerationBlocked(decision)
    assert blocked.private_cause is cause and blocked.decision is decision
    assert blocked.args == (generation.UNKNOWN_MESSAGE,)
    assert str(blocked) == generation.UNKNOWN_MESSAGE
    expected = {"status": "UNKNOWN", "allowed": False, "message_key": "data_generation_unknown",
                "message": generation.UNKNOWN_MESSAGE, "version": None, "minimum_version": None}
    assert dict(decision) == expected
    assert json.dumps(decision) == json.dumps(expected)
    assert "private_cause" not in repr(decision)
    assert str(marker) not in json.dumps(cause) and "synthetic private detail" not in json.dumps(cause)


def test_diagnostic_leaf_remains_pinned_unconsumed_inventory_source(tmp_path):
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    pass\n")
    leaf = Path(__file__).resolve().parents[1] / "kmtech_shared/diagnostic_log.py"
    assert hashlib.sha256(leaf.read_bytes()).hexdigest() == module.SHARED_UNUSED_DIAGNOSTIC_SHA256
    shutil.copyfile(leaf, tmp_path / "kmtech_shared/diagnostic_log.py")
    inventory = module.derive_inventory(tmp_path)
    assert inventory["uncovered_direct_mutation_functions"] == []
    assert inventory["pinned_unused_sources"] == [{"path": "kmtech_shared/diagnostic_log.py", "sha256": module.SHARED_UNUSED_DIAGNOSTIC_SHA256}]

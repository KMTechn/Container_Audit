"""FAILED removal must establish each proof before touching user setup."""
import json
import os

import pytest

from tests.test_support_removal_after_update import (
    signed_packet, signed_proof, support_removal_packets, updated_packets,
)


@pytest.fixture
def failed_packets(updated_packets, monkeypatch):
    import auto_update as update
    import current_user_onboarding as onboarding
    from kmtech_shared import data_generation as generation

    packets = updated_packets
    state_path = packets.control / "transition.json"
    state = update.read_json(state_path)
    state.update(phase="FAILED", reason="readiness verification failed",
                 last_ready_error="readiness result unavailable")
    update.write_json_durable(state_path, state)
    packets.proofs = []
    verify = onboarding.verify_bootstrap_integrity
    probe = generation.probe_downgrade

    def verified(paths, **kwargs):
        packets.proofs.append(paths.app_root)
        return verify(paths, **kwargs)

    def observed(_control):
        packets.proofs.append("census")
        return []

    def probed(*args, **kwargs):
        packets.proofs.append("generation")
        decision = probe(*args, **kwargs)
        packets.proofs.append("generation_" + decision["status"])
        return decision

    monkeypatch.setattr(onboarding, "verify_bootstrap_integrity", verified)
    monkeypatch.setattr(update, "process_snapshot", observed)
    monkeypatch.setattr(generation, "probe_downgrade", probed)
    original_markers = [(path, path.read_bytes()) for path in packets.markers]
    try:
        yield packets
    finally:
        for path, raw in original_markers:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)


def test_failed_support_removal_requires_all_four_proofs(failed_packets):
    packets = failed_packets
    state = (packets.control / "transition.json").read_bytes()
    markers = [path.read_bytes() for path in packets.markers]
    event = packets.seed.event.read_bytes()
    assert packets.remove()["status"] == "PASS_DATA_PRESERVED"
    assert packets.active in packets.proofs
    assert "census" in packets.proofs and "generation" in packets.proofs
    assert (packets.control / "transition.json").read_bytes() == state
    assert [path.read_bytes() for path in packets.markers] == markers
    assert packets.seed.event.read_bytes() == event


@pytest.mark.parametrize("failure", ["code", "writer", "generation", "fence", "prepared", "missing_marker"])
def test_failed_support_removal_rejects_each_unproven_condition(failed_packets, monkeypatch, failure):
    import auto_update as update
    import current_user_onboarding as onboarding
    import writer_session_fence as fence

    packets = failed_packets
    expected_proof = packets.active
    if failure == "code":
        with (packets.active / "app/Container_Audit.py").open("ab") as target:
            target.write(b"\n# changed code\n")
    elif failure == "writer":
        def observed(_control):
            packets.proofs.append("census")
            return [{"pid": os.getpid() + 1, "observable": True, "role": "gui"}]
        monkeypatch.setattr(update, "process_snapshot", observed)
        expected_proof = "census"
    elif failure == "generation":
        for path in packets.markers:
            marker = json.loads(path.read_bytes())
            marker["data_compatible_min_version"] = "v99.0.0"
            marker["version"] = "v99.0.0"
            path.write_text(json.dumps(marker), encoding="utf-8")
        expected_proof = "generation_REFUSE"
    elif failure == "fence":
        def active(*args, **kwargs):
            packets.proofs.append("fence")
            return {"status": "INSTALLING"}
        monkeypatch.setattr(fence, "active_fence", active)
        expected_proof = "fence"
    elif failure == "prepared":
        def pending(*args, **kwargs):
            packets.proofs.append("prepared")
            return True
        monkeypatch.setattr(update, "prepared_pending", pending)
        expected_proof = "prepared"
    else:
        for path in packets.markers:
            path.unlink()
        expected_proof = "generation"

    state = (packets.control / "transition.json").read_bytes()
    event = packets.seed.event.read_bytes()
    with pytest.raises(onboarding.CurrentUserOnboardingError) as caught:
        packets.remove()
    assert expected_proof in packets.proofs
    assert caught.value.__cause__.decision["status"] == "UNKNOWN"
    assert packets.seed.observed == []
    assert (packets.control / "transition.json").read_bytes() == state
    assert packets.seed.event.read_bytes() == event


def test_failed_support_removal_rechecks_census_after_generation_probe(failed_packets, monkeypatch):
    import auto_update as update
    import current_user_onboarding as onboarding

    packets = failed_packets
    calls = []

    def observed(_control):
        calls.append(True)
        return [] if len(calls) == 1 else [{"pid": os.getpid() + 1, "observable": True}]

    monkeypatch.setattr(update, "process_snapshot", observed)
    with pytest.raises(onboarding.CurrentUserOnboardingError):
        packets.remove()
    assert len(calls) == 2
    assert packets.seed.observed == []

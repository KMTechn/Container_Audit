"""G15: code restoration does not prove the restored relay is READY."""
import json

import auto_update as update


def test_restored_code_requires_fresh_relay_ready_before_rollback_completion(tmp_path):
    previous = "a" * 40
    failed = "b" * 40
    state = {
        "schema": update.SCHEMA,
        "transition_id": "d" * 32,
        "phase": "ROLLBACK_PENDING",
        "previous_sha": previous,
        "candidate_sha": failed,
        "failed_shas": [failed],
        "failure_decision": {"selected_sha": previous},
        "trial_pid": 123,
        "trial_sha": failed,
        "trial_started_at": "2026-10-15T00:00:00Z",
    }
    restored = update.rollback_transition(
        state, writers_absent=True, previous_verified=True, durable_rollback=True,
        nonce="c" * 32, now="2026-10-15T00:01:00Z",
    )
    # Exercise the real durable publication helper and reread the persisted state.
    update.persist_switch(tmp_path, restored, previous)
    restored = update.read_json(tmp_path / "transition.json")
    pointer = update.read_json(tmp_path / "active.json")
    (tmp_path / "same-class-g15-observation.json").write_text(
        json.dumps({
            "phase": restored["phase"],
            "confirmed_at_present": "confirmed_at" in restored,
            "previous_pointer_restored": pointer["sha"] == previous,
            "trial_cleared": restored["trial_pid"] is None,
            "failed_candidate_preserved": failed in restored["failed_shas"],
        }), encoding="utf-8",
    )
    assert pointer["sha"] == previous
    assert restored["previous_sha"] == previous
    assert failed in restored["failed_shas"]
    assert restored["trial_pid"] is None
    assert restored["phase"] == "ROLLBACK_PENDING_READY", (
        "restored code has no fresh ordinary-relay READY proof"
    )
    assert "confirmed_at" not in restored

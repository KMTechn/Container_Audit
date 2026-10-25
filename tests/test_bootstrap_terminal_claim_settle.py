"""A published terminal record does not settle the SYSTEM apply claim."""
import contextlib

import pytest

import auto_update as updates
from tests.test_bootstrap_live_apply_wait import ordinary, scene, world


@pytest.mark.parametrize("claim", ["LIVE", "UNKNOWN"])
@pytest.mark.parametrize("terminal", ["CONFIRMED", "DEFERRED"])
def test_terminal_publication_waits_for_claim_none(scene, monkeypatch, claim, terminal):
    w = world(scene, monkeypatch, applied=260, terminal=terminal,
              normal_stop=False, decision_at=280, released_at=281)

    @contextlib.contextmanager
    def unlocked(*args, **kwargs):
        yield True

    def unsettled(*args):
        return ("NONE" if w.s.clock[0] >= w.released else
                claim if w.s.clock[0] >= w.decided else "LIVE")

    monkeypatch.setattr(updates, "startup_update_lock", unlocked)
    monkeypatch.setattr(updates, "apply_claim_status", unsettled)
    result = updates._bootstrap(w.s.control.parent, [], role="gui")
    w.s.write(w.s.control / "terminal-claim-settle.json", {
        "rc": result, "finished": w.s.clock[0], "decision_at": w.decided,
        "claim_settled_at": w.released, "popens": w.popens,
    })
    assert result == 0
    assert w.s.clock[0] == pytest.approx(w.released)
    assert all(row["at"] >= w.released for row in ordinary(w))
    assert not w.progress

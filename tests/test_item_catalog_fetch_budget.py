"""The lane's 40-second retry admission budget uses a monotonic clock."""
import json

import pytest
import requests

import item_catalog_sync as sync
from tests.test_item_catalog_first_fetch import catalog, refresh


@pytest.mark.parametrize("attempt_seconds,expected_calls,elapsed", [
    (20.0, 2, 40.25),
    (0.0, 3, 0.5),
    (20.001, 1, 20.001),
], ids=["slow-two", "immediate-three", "insufficient-next-window"])
def test_first_fetch_retry_requires_twenty_seconds_remaining(
    catalog, monkeypatch, attempt_seconds, expected_calls, elapsed,
):
    clock, calls, gaps = [0.0], [], []
    monkeypatch.setattr(sync, "_first_fetch_clock", lambda: clock[0], raising=False)

    def pause(seconds):
        gaps.append(seconds)
        clock[0] += seconds

    def transport(url, **kwargs):
        calls.append({"at": clock[0], "timeout": kwargs["timeout"]})
        clock[0] += attempt_seconds
        raise requests.ReadTimeout()

    monkeypatch.setattr(sync, "_first_fetch_pause", pause)
    with pytest.raises(sync.ItemCatalogSyncError):
        refresh(catalog, transport)
    (catalog[0].parent / "retry-budget-observation.json").write_text(json.dumps({
        "calls": calls, "gaps": gaps, "elapsed": clock[0],
        "attempt_seconds": attempt_seconds,
    }), encoding="utf-8")
    assert len(calls) == expected_calls
    assert [row["timeout"] for row in calls] == [10.0] * expected_calls
    assert gaps == [0.25] * (expected_calls - 1)
    assert clock[0] == pytest.approx(elapsed)

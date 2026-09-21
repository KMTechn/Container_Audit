"""Real-child regression for the HKCU resident relay writer deadlock.

`user_relay.main` drives `run_session_direct_sync_once`, which spawns the
production relay runner as a separate OS process. The child takes the same
per-user writer admission for its own spanning lease, so a parent that held
admission across `subprocess.run` starved the child out with
`WRITER_GATE_TIMEOUT`. Nothing here mocks `subprocess` or `requests.Session`
on the success path: a real child either completes or this file turns red.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

import user_relay
import writer_session_fence as fence
from direct_sync_push import DEFAULT_ENDPOINT_PATH

from tests.test_real_child_http_regression import (
    CSV_NAME,
    ROOT,
    _loopback_https,
    _write_child_runtime,
    _write_csv,
)
from tests.test_writer_session_fence import _active_payload, _write_active


@pytest.mark.parametrize("root_selection", ["environment", "logon_argument"])
def test_resident_relay_main_runs_a_real_child_to_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_selection: str
) -> None:
    """The resident relay must not hold writer admission across the spawn.

    A parent that still held it would leave the child at WRITER_GATE_TIMEOUT,
    so a real child that reaches rc 0 and POSTs the CSV is the proof.
    """

    with _loopback_https(tmp_path, monkeypatch) as bundle:
        data_root = tmp_path / "data-root"
        events = data_root / "events"
        csv_bytes = _write_csv(events / CSV_NAME)
        direct_sync_root = data_root / "direct_sync"
        _write_child_runtime(direct_sync_root, bundle)
        root_arguments = []
        if root_selection == "environment":
            monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(data_root))
        else:
            monkeypatch.delenv("CONTAINER_AUDIT_DATA_ROOT", raising=False)
            root_arguments = ["--data-root", str(data_root)]

        exit_code = user_relay.main(
            [
                "--app-root",
                str(ROOT),
                *root_arguments,
                "--once",
            ]
        )

        assert bundle["marker_path"].is_file(), (
            "relay child did not load tests/sitecustomize.py; writer isolation is unproven"
        )
        status = json.loads(
            user_relay.user_relay_status_path(direct_sync_root).read_text(
                encoding="utf-8"
            )
        )
        cycle = status["last_cycle"]
        assert cycle["process_status"] == "PASS", cycle
        assert cycle["process_returncode"] == 0, cycle
        assert exit_code == 0, status
        ingest_bodies = bundle["recorded"].bodies_for(DEFAULT_ENDPOINT_PATH)
        assert ingest_bodies, (
            "resident relay child never POSTed /api/producer-ingest/v1/source-file"
        )
        assert csv_bytes in ingest_bodies[0]


def test_resident_relay_main_denies_under_fence_before_any_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An active fence must stop the resident relay before the child exists."""

    import direct_sync_auto_bootstrap as bootstrap

    control = tmp_path / "control"
    _write_active(control, _active_payload())
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(tmp_path / "data-root"))
    canonical = fence.canonical_control_root()
    canonical.mkdir(parents=True, exist_ok=True)
    active = canonical / fence.ACTIVE_FILENAME
    active.write_bytes((control / fence.ACTIVE_FILENAME).read_bytes())
    before = (active.read_bytes(), active.stat().st_mtime_ns)
    direct_sync_root = tmp_path / "direct-sync"
    spawns: list[object] = []

    def forbidden_run(*args: object, **kwargs: object) -> None:
        spawns.append(args)
        raise AssertionError("the relay child must not be spawned under an active fence")

    monkeypatch.setattr(bootstrap.subprocess, "run", forbidden_run)

    with pytest.raises(fence.WriterFencedError) as exc_info:
        user_relay.main(
            [
                "--app-root",
                str(ROOT),
                "--direct-sync-root",
                str(direct_sync_root),
                "--scan-source-dir",
                str(tmp_path / "events"),
                "--once",
            ]
        )

    assert exc_info.value.code == "ACTIVE_WRITER_FENCE"
    assert spawns == []
    assert not direct_sync_root.exists()
    assert not (tmp_path / "data-root").exists()
    assert (active.read_bytes(), active.stat().st_mtime_ns) == before

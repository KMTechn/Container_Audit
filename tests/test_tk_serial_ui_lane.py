from __future__ import annotations

from collections import deque
import importlib
import threading
import time

import pytest

pytestmark = pytest.mark.usefixtures("owned_tk_workers")


class FakeTkRoot:
    def __init__(self) -> None:
        self.owner_thread_id = threading.get_ident()
        self.jobs = deque()
        self.cancelled: set[str] = set()
        self.after_threads: list[int] = []
        self.destroyed = False
        self._next_job = 0

    def after(self, delay_ms, callback, *args):
        thread_id = threading.get_ident()
        self.after_threads.append(thread_id)
        if thread_id != self.owner_thread_id:
            raise AssertionError("worker called Tk.after")
        self._next_job += 1
        job_id = f"job-{self._next_job}"
        self.jobs.append((job_id, int(delay_ms), callback, args))
        return job_id

    def after_cancel(self, job_id):
        if threading.get_ident() != self.owner_thread_id:
            raise AssertionError("worker called Tk.after_cancel")
        self.cancelled.add(str(job_id))

    def destroy(self):
        assert threading.get_ident() == self.owner_thread_id
        self.destroyed = True

    def run_one(self) -> bool:
        while self.jobs:
            job_id, _delay, callback, args = self.jobs.popleft()
            if job_id in self.cancelled:
                continue
            callback(*args)
            return True
        return False

    def run_until(self, predicate, *, timeout=2.0) -> None:
        deadline = time.monotonic() + timeout
        while not predicate():
            ran = self.run_one()
            if not ran:
                threading.Event().wait(0.002)
            if time.monotonic() >= deadline:
                raise AssertionError("fake Tk pump did not reach the expected state")


def _symbols():
    module = importlib.import_module("tk_serial_ui_lane")
    return module, module.LaneTask, module.TkSerialUiLane


def _close(root, lane) -> None:
    if getattr(lane, "state", "") == "CLOSED":
        return
    lane.close_idle()
    root.run_until(lambda: lane.state == "CLOSED")


def test_completion_handle_reports_timeout_until_work_finishes():
    module, _, _ = _symbols()
    handle = module.TaskHandle()
    assert handle.join(timeout=0) is False
    handle._mark_work_done()
    assert handle.join(timeout=0) is True


def test_assertion_failure_still_drains_lane_and_pytest_exits(tmp_path):
    import json
    import subprocess
    import sys

    (tmp_path / "conftest.py").write_text(
        "from tests.conftest import owned_tk_workers\n", encoding="utf-8")
    test_file = tmp_path / "test_forced_failure.py"
    test_file.write_text(
        "import pytest\n"
        "from tests.test_tk_serial_ui_lane import FakeTkRoot\n"
        "from tk_serial_ui_lane import TkSerialUiLane, LaneTask\n"
        "@pytest.mark.usefixtures('owned_tk_workers')\n"
        "def test_forced_failure():\n"
        "    lane = TkSerialUiLane(FakeTkRoot())\n"
        "    lane.submit(LaneTask('checkpoint', 0, lambda: lane.call_ui_sync(lambda: True), lambda value: None, lambda exc: None))\n"
        "    assert False, 'intentional assertion before close'\n", encoding="utf-8")
    result_path = tmp_path / "threads.json"
    probe = (
        "import json, pathlib, pytest, sys, threading; "
        "code = pytest.main(['-q', '-p', 'no:cacheprovider', sys.argv[1], '--basetemp', sys.argv[3]]); "
        "live = [t.name for t in threading.enumerate() if t is not threading.main_thread() and not t.daemon]; "
        "pathlib.Path(sys.argv[2]).write_text(json.dumps(live), encoding='utf-8'); sys.exit(code)"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", probe, str(test_file), str(result_path), str(tmp_path / "child")],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "1 failed" in result.stdout
    assert json.loads(result_path.read_text(encoding="utf-8")) == []


def test_blocked_work_does_not_block_tk_pump():
    module, LaneTask, TkSerialUiLane = _symbols()
    assert module.UI_LANE_SPEC == "kmtech-tk-ui-lane-v1"
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    gate = threading.Event()
    started = threading.Event()
    heartbeats = []

    def work():
        started.set()
        assert gate.wait(timeout=2.0)
        return "done"

    started_at = time.perf_counter()
    admission = lane.submit(
        LaneTask("blocked", 1, work, lambda _value: None, lambda exc: pytest.fail(str(exc)))
    )
    elapsed = time.perf_counter() - started_at
    root.after(0, lambda: heartbeats.append(threading.get_ident()))
    root.run_until(lambda: bool(heartbeats))

    assert admission.accepted is True
    assert elapsed < 0.1
    assert started.wait(timeout=1.0)
    assert heartbeats == [root.owner_thread_id]
    assert lane.worker_thread_id != root.owner_thread_id
    gate.set()
    root.run_until(lambda: not lane.is_busy())
    _close(root, lane)


def test_exactly_one_worker_and_no_overlap():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    active = 0
    max_active = 0
    worker_ids = []

    def work():
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        worker_ids.append(threading.get_ident())
        active -= 1
        return len(worker_ids)

    for index in range(2):
        assert lane.submit(LaneTask(f"op-{index}", index, work, lambda _value: None, pytest.fail)).accepted
        root.run_until(lambda: not lane.is_busy())

    assert len(set(worker_ids)) == 1
    assert worker_ids[0] == lane.worker_thread_id
    assert max_active == 1
    _close(root, lane)


def test_worker_never_calls_tk_or_after():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    work_threads = []
    finish_threads = []
    assert lane.submit(
        LaneTask(
            "thread-affinity",
            1,
            lambda: work_threads.append(threading.get_ident()),
            lambda _value: finish_threads.append(threading.get_ident()),
            pytest.fail,
        )
    ).accepted
    root.run_until(lambda: not lane.is_busy())

    assert work_threads == [lane.worker_thread_id]
    assert finish_threads == [root.owner_thread_id]
    assert set(root.after_threads) == {root.owner_thread_id}
    _close(root, lane)


def test_success_finish_runs_once_on_tk():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    finished = []
    failed = []
    lane.submit(
        LaneTask(
            "success",
            1,
            lambda: 42,
            lambda value: finished.append((value, threading.get_ident())),
            failed.append,
        )
    )
    root.run_until(lambda: not lane.is_busy())
    for _ in range(3):
        root.run_one()

    assert finished == [(42, root.owner_thread_id)]
    assert failed == []
    _close(root, lane)


def test_exception_reaches_fail_once_on_tk():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    finished = []
    failed = []

    def work():
        raise ValueError("secret detail must not reach the operator")

    lane.submit(
        LaneTask(
            "failure",
            1,
            work,
            finished.append,
            lambda exc: failed.append((type(exc), threading.get_ident())),
        )
    )
    root.run_until(lambda: not lane.is_busy())
    for _ in range(3):
        root.run_one()

    assert finished == []
    assert failed == [(ValueError, root.owner_thread_id)]
    _close(root, lane)


def test_finish_failure_breaks_lane():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    faults = []
    lane = TkSerialUiLane(root, poll_ms=1, on_runner_fault=lambda exc: faults.append(type(exc)))

    def broken_finish(_value):
        raise RuntimeError("render failed")

    lane.submit(LaneTask("broken-finish", 1, lambda: "ok", broken_finish, pytest.fail))
    root.run_until(lambda: lane.state == "BROKEN")
    rejected = lane.submit(LaneTask("must-reject", 2, lambda: None, lambda _value: None, pytest.fail))

    assert rejected.accepted is False
    assert rejected.reason == "broken"
    assert faults == [RuntimeError]
    lane.close_idle()
    root.run_until(lambda: lane.state == "CLOSED")


def test_busy_reject_preserves_input():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    gate = threading.Event()
    raw_input = {"value": "PRODUCT-B"}
    first = lane.submit(
        LaneTask("first", 1, lambda: gate.wait(timeout=2.0), lambda _value: None, pytest.fail)
    )
    second = lane.submit(
        LaneTask("second", 1, lambda: raw_input.clear(), lambda _value: None, pytest.fail)
    )

    assert first.accepted is True
    assert second.accepted is False
    assert second.reason == "busy"
    assert raw_input == {"value": "PRODUCT-B"}
    gate.set()
    root.run_until(lambda: not lane.is_busy())
    _close(root, lane)


def test_fifo_ui_call_before_final_result():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    order = []

    def work():
        value = lane.call_ui_sync(lambda: order.append("checkpoint") or "prepared")
        order.append(f"worker:{value}")
        return "final"

    lane.submit(LaneTask("checkpoint", 1, work, lambda value: order.append(value), pytest.fail))
    root.run_until(lambda: not lane.is_busy())

    assert order == ["checkpoint", "worker:prepared", "final"]
    _close(root, lane)


def test_stale_generation_rejects_sync_checkpoint_and_releases_waiter():
    module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    generation = {"value": 1}
    lane = TkSerialUiLane(
        root,
        poll_ms=1,
        generation_provider=lambda: generation["value"],
    )
    started = threading.Event()
    release = threading.Event()
    checkpoint_calls = []
    worker_failures = []
    finished = []
    failed = []

    def work():
        started.set()
        assert release.wait(timeout=2.0)
        try:
            return lane.call_ui_sync(lambda: checkpoint_calls.append("called"))
        except BaseException as exc:
            worker_failures.append(exc)
            raise

    admission = lane.submit(
        LaneTask("stale-checkpoint", 1, work, finished.append, failed.append)
    )
    assert admission.accepted is True
    assert admission.handle is not None
    assert started.wait(timeout=1.0)

    generation["value"] = 2
    release.set()
    root.run_until(lambda: not lane.is_busy())

    assert checkpoint_calls == []
    assert admission.handle.is_alive() is False
    assert len(worker_failures) == 1
    assert isinstance(worker_failures[0], module.StaleUiCheckpointError)
    assert worker_failures[0].code == "UI_LANE_STALE_CHECKPOINT"
    assert worker_failures[0].task_generation == 1
    assert worker_failures[0].current_generation == 2
    assert admission.handle.stale_generation_error is worker_failures[0]
    assert finished == []
    assert failed == []
    _close(root, lane)


def test_on_idle_barrier_order():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    order = []
    nested_admissions = []

    def on_idle():
        order.append(("idle", lane.is_busy()))
        nested_admissions.append(
            lane.submit(LaneTask("too-early", 1, lambda: None, lambda _value: None, pytest.fail))
        )

    lane.submit(
        LaneTask(
            "barrier",
            1,
            lambda: order.append("work") or "ok",
            lambda _value: order.append("finish"),
            pytest.fail,
            on_idle=on_idle,
        )
    )
    root.run_until(lambda: not lane.is_busy() and bool(nested_admissions))

    assert order == ["work", "finish", ("idle", False)]
    assert nested_admissions[0].accepted is False
    assert nested_admissions[0].reason == "busy"
    _close(root, lane)


@pytest.mark.parametrize("terminal_path", ["success", "failure"])
def test_stale_terminal_generation_skips_callbacks_and_domain_transition(
    terminal_path,
):
    module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    generation = {"value": 1}
    lane = TkSerialUiLane(
        root,
        poll_ms=1,
        generation_provider=lambda: generation["value"],
    )
    started = threading.Event()
    release = threading.Event()
    finished = []
    failed = []
    stale_settles = []
    domain = {"state": "generation-1"}

    def work():
        started.set()
        assert release.wait(timeout=2.0)
        if terminal_path == "failure":
            raise ValueError("stale failure")
        return "stale success"

    admission = lane.submit(
        LaneTask(
            "stale-terminal",
            1,
            work,
            lambda value: (finished.append(value), domain.update(state="stale")),
            lambda exc: (failed.append(exc), domain.update(state="stale")),
            on_stale=lambda: stale_settles.append((lane.is_busy(), lane.state)),
        )
    )
    assert admission.handle is not None
    assert started.wait(timeout=1.0)
    generation["value"] = 2
    domain["state"] = "generation-2"
    release.set()
    root.run_until(lambda: not lane.is_busy())

    assert finished == []
    assert failed == []
    assert stale_settles == [(True, "BUSY")]
    assert domain == {"state": "generation-2"}
    assert isinstance(
        admission.handle.stale_generation_error,
        module.StaleUiResultError,
    )
    assert admission.handle.stale_generation_error.code == "UI_LANE_STALE_RESULT"
    assert admission.handle.stale_generation_error.task_generation == 1
    assert admission.handle.stale_generation_error.current_generation == 2
    assert lane.state == "IDLE"
    _close(root, lane)


def test_timeout_is_typed_and_ui_stays_live():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    gate = threading.Event()
    heartbeat = []
    failures = []

    class TypedTimeout(TimeoutError):
        commit_state = "unknown"
        retryable = True

    def work():
        assert gate.wait(timeout=2.0)
        raise TypedTimeout("safe timeout")

    lane.submit(LaneTask("timeout", 1, work, pytest.fail, failures.append))
    root.after(0, lambda: heartbeat.append("alive"))
    root.run_until(lambda: heartbeat == ["alive"])
    gate.set()
    root.run_until(lambda: not lane.is_busy())

    assert len(failures) == 1
    assert isinstance(failures[0], TypedTimeout)
    assert failures[0].commit_state == "unknown"
    _close(root, lane)


def test_close_stops_admission_and_drains_before_destroy():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    gate = threading.Event()
    order = []

    def work():
        assert gate.wait(timeout=2.0)
        order.append("work")
        return "done"

    lane.submit(LaneTask("mutation", 1, work, lambda _value: order.append("finish"), pytest.fail))

    def after_drain():
        order.append("recovery-save")
        assert lane.worker_thread.is_alive() is False
        order.append("worker-close")
        root.destroy()
        order.append("destroy")

    lane.drain_then(after_drain)
    rejected = lane.submit(LaneTask("late", 1, lambda: None, lambda _value: None, pytest.fail))
    assert rejected.accepted is False
    assert rejected.reason == "closing"
    assert root.destroyed is False
    gate.set()
    root.run_until(lambda: root.destroyed)

    assert order == ["work", "finish", "recovery-save", "worker-close", "destroy"]
    assert lane.state == "CLOSED"


def test_call_ui_sync_round_trip_and_exception():
    _module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    round_trip = []
    failures = []

    def work():
        round_trip.append(lane.call_ui_sync(lambda left, right: left + right, 20, 22))

        def fail_checkpoint():
            raise LookupError("checkpoint failed")

        lane.call_ui_sync(fail_checkpoint)

    lane.submit(LaneTask("ui-call", 1, work, pytest.fail, failures.append))
    root.run_until(lambda: not lane.is_busy())

    assert round_trip == [42]
    assert len(failures) == 1
    assert isinstance(failures[0], LookupError)
    _close(root, lane)


def test_periodic_trigger_coalesces_while_busy():
    module, LaneTask, TkSerialUiLane = _symbols()
    root = FakeTkRoot()
    lane = TkSerialUiLane(root, poll_ms=1)
    trigger = module.CoalescingTrigger(lane)
    gate = threading.Event()
    calls = []

    def task_factory():
        return LaneTask(
            "poll",
            1,
            lambda: gate.wait(timeout=2.0) or "done",
            lambda _value: calls.append("finish"),
            pytest.fail,
        )

    first = trigger.trigger(task_factory)
    second = trigger.trigger(task_factory)
    third = trigger.trigger(task_factory)

    assert first.accepted is True
    assert second.accepted is False
    assert third.accepted is False
    assert trigger.pending_count == 1
    gate.set()
    root.run_until(lambda: calls == ["finish", "finish"])
    assert trigger.pending_count == 0
    _close(root, lane)

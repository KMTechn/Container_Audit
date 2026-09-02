"""Tk-owned result pump with one serial foreground worker.

The lane deliberately owns execution only.  Durable scan/input queues remain
application state and must not be placed in the in-memory task queue here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import queue
import threading
from typing import Any, Callable, Optional


UI_LANE_SPEC = "kmtech-tk-ui-lane-v1"

LANE_IDLE = "IDLE"
LANE_BUSY = "BUSY"
LANE_DRAINING = "DRAINING"
LANE_BROKEN = "BROKEN"
LANE_CLOSED = "CLOSED"

DRAIN_TO_TERMINAL = "DRAIN_TO_TERMINAL"
DRAIN_TO_DURABLE_HANDOFF = "DRAIN_TO_DURABLE_HANDOFF"
_SHUTDOWN_POLICIES = {DRAIN_TO_TERMINAL, DRAIN_TO_DURABLE_HANDOFF}


class StaleUiGenerationError(RuntimeError):
    """Typed record that a lane result belongs to an obsolete UI generation."""

    code = "UI_LANE_STALE_GENERATION"

    def __init__(
        self,
        task_generation: int,
        current_generation: int | None = None,
    ) -> None:
        self.task_generation = int(task_generation)
        self.current_generation = int(
            task_generation if current_generation is None else current_generation
        )
        super().__init__(self.code)


class StaleUiCheckpointError(StaleUiGenerationError):
    """Raised back to a worker whose synchronous UI checkpoint is stale."""

    code = "UI_LANE_STALE_CHECKPOINT"


class StaleUiResultError(StaleUiGenerationError):
    """Recorded when a terminal result is skipped for a stale generation."""

    code = "UI_LANE_STALE_RESULT"


@dataclass(frozen=True)
class LaneTask:
    name: str
    generation: int
    work: Callable[[], Any]
    finish: Callable[[Any], None]
    fail: Callable[[BaseException], None]
    on_idle: Optional[Callable[[], None]] = None
    cancel_safe: bool = False
    shutdown_policy: str = DRAIN_TO_TERMINAL
    on_stale: Optional[Callable[[], None]] = None

    def __post_init__(self) -> None:
        if not str(self.name or "").strip():
            raise ValueError("lane task name is required")
        if self.shutdown_policy not in _SHUTDOWN_POLICIES:
            raise ValueError("invalid lane shutdown policy")
        for callback in (self.work, self.finish, self.fail):
            if not callable(callback):
                raise TypeError("lane task callbacks must be callable")


class TaskHandle:
    """Compatibility-sized completion handle for deterministic tests/adapters."""

    def __init__(self) -> None:
        self._work_done = threading.Event()
        self.stale_generation_error: StaleUiGenerationError | None = None

    def _mark_work_done(self) -> None:
        self._work_done.set()

    def join(self, timeout: float | None = None) -> None:
        self._work_done.wait(timeout)

    def is_alive(self) -> bool:
        return not self._work_done.is_set()

@dataclass(frozen=True)
class Admission:
    accepted: bool
    op_id: int | None = None
    reason: str = ""
    handle: TaskHandle | None = None


@dataclass
class _UiCall:
    callback: Callable[..., Any]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    event: threading.Event
    result: Any = None
    error: BaseException | None = None


@dataclass(frozen=True)
class _Envelope:
    sequence: int
    op_id: int
    generation: int
    kind: str
    task: LaneTask | None = None
    value: Any = None


@dataclass(frozen=True)
class _QueuedTask:
    op_id: int
    task: LaneTask
    handle: TaskHandle


_STOP = object()


class TkSerialUiLane:
    """Run blocking work on one non-daemon thread and apply results on Tk."""

    def __init__(
        self,
        root: Any,
        *,
        poll_ms: int = 15,
        max_results_per_tick: int = 16,
        generation_provider: Callable[[], int] | None = None,
        on_runner_fault: Callable[[BaseException], None] | None = None,
    ) -> None:
        self._root = root
        self._owner_thread_id = threading.get_ident()
        self._poll_ms = max(1, int(poll_ms))
        self._max_results_per_tick = max(1, int(max_results_per_tick))
        self._generation_provider = generation_provider
        self._on_runner_fault = on_runner_fault
        self._state_lock = threading.RLock()
        self._sequence_lock = threading.Lock()
        self._state = LANE_IDLE
        self._active: _QueuedTask | None = None
        self._idle_barrier = False
        self._next_op_id = 0
        self._next_sequence = 0
        self._fault_presented = False
        self._task_queue: queue.Queue[Any] = queue.Queue(maxsize=1)
        self._result_queue: queue.Queue[_Envelope] = queue.Queue()
        self._drain_callbacks: list[Callable[[], None]] = []
        self._worker_thread_id: int | None = None
        self._worker_started = threading.Event()
        self._stop_sent = False
        self._pump_job: Any = None
        self.worker_thread = threading.Thread(
            target=self._worker_main,
            name="container-audit-tk-ui-lane",
            daemon=False,
        )
        self.worker_thread.start()
        if not self._worker_started.wait(timeout=2.0):
            raise RuntimeError("Tk UI lane worker did not start")
        self._schedule_pump()

    @property
    def state(self) -> str:
        with self._state_lock:
            return self._state

    @property
    def worker_thread_id(self) -> int | None:
        return self._worker_thread_id

    def _assert_owner(self) -> None:
        if threading.get_ident() != self._owner_thread_id:
            raise RuntimeError("Tk UI lane control method called outside the Tk owner")

    def _next_result_sequence(self) -> int:
        with self._sequence_lock:
            self._next_sequence += 1
            return self._next_sequence

    def _generation_is_current(self, generation: int) -> bool:
        if self._generation_provider is None:
            return True
        return int(self._generation_provider()) == int(generation)

    def _schedule_pump(self) -> None:
        self._assert_owner()
        if self.state == LANE_CLOSED or self._pump_job is not None:
            return
        self._pump_job = self._root.after(self._poll_ms, self._pump)

    def submit(self, task: LaneTask) -> Admission:
        self._assert_owner()
        if not isinstance(task, LaneTask):
            raise TypeError("submit requires LaneTask")
        with self._state_lock:
            if self._state == LANE_BROKEN:
                return Admission(False, reason="broken")
            if self._state in {LANE_DRAINING, LANE_CLOSED}:
                return Admission(False, reason="closing")
            if self._active is not None or self._idle_barrier or self._state == LANE_BUSY:
                return Admission(False, reason="busy")
            self._next_op_id += 1
            handle = TaskHandle()
            queued = _QueuedTask(self._next_op_id, task, handle)
            self._active = queued
            self._state = LANE_BUSY
        try:
            self._task_queue.put_nowait(queued)
        except queue.Full as exc:
            with self._state_lock:
                self._active = None
                self._state = LANE_BROKEN
            self._present_fault(exc)
            return Admission(False, reason="broken")
        return Admission(True, op_id=queued.op_id, handle=handle)

    def is_busy(self) -> bool:
        with self._state_lock:
            return self._active is not None

    def call_ui_sync(self, callback: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if threading.get_ident() == self._owner_thread_id:
            return callback(*args, **kwargs)
        with self._state_lock:
            active = self._active
            state = self._state
        if active is None or state in {LANE_BROKEN, LANE_CLOSED}:
            raise RuntimeError("Tk UI call has no active lane task")
        ui_call = _UiCall(callback, tuple(args), dict(kwargs), threading.Event())
        self._result_queue.put(
            _Envelope(
                self._next_result_sequence(),
                active.op_id,
                active.task.generation,
                "ui_call",
                value=ui_call,
            )
        )
        ui_call.event.wait()
        if ui_call.error is not None:
            raise ui_call.error
        return ui_call.result

    def stop_accepting(self) -> None:
        self._assert_owner()
        with self._state_lock:
            if self._state in {LANE_CLOSED, LANE_BROKEN}:
                return
            self._state = LANE_DRAINING

    def drain_then(self, callback: Callable[[], None]) -> None:
        self._assert_owner()
        if not callable(callback):
            raise TypeError("drain callback must be callable")
        with self._state_lock:
            if self._state == LANE_CLOSED:
                callback()
                return
            self._drain_callbacks.append(callback)
            active = self._active
            if self._state != LANE_BROKEN:
                self._state = LANE_DRAINING
        if active is None:
            self._complete_close()

    def close_idle(self) -> None:
        self._assert_owner()
        with self._state_lock:
            if self._state == LANE_CLOSED:
                return
            active = self._active
            if self._state != LANE_BROKEN:
                self._state = LANE_DRAINING
        if active is None:
            self._complete_close()

    def mark_broken(self, exc: BaseException) -> None:
        """Enter the fail-closed terminal state from the Tk owner."""

        self._assert_owner()
        self._break_lane(exc)

    def _worker_main(self) -> None:
        self._worker_thread_id = threading.get_ident()
        self._worker_started.set()
        while True:
            queued = self._task_queue.get()
            try:
                if queued is _STOP:
                    return
                assert isinstance(queued, _QueuedTask)
                try:
                    value = queued.task.work()
                    envelope = _Envelope(
                        self._next_result_sequence(),
                        queued.op_id,
                        queued.task.generation,
                        "success",
                        task=queued.task,
                        value=value,
                    )
                except BaseException as exc:
                    envelope = _Envelope(
                        self._next_result_sequence(),
                        queued.op_id,
                        queued.task.generation,
                        "failure",
                        task=queued.task,
                        value=exc,
                    )
                self._result_queue.put(envelope)
                queued.handle._mark_work_done()
            finally:
                self._task_queue.task_done()

    def _pump(self) -> None:
        self._assert_owner()
        self._pump_job = None
        processed = 0
        while processed < self._max_results_per_tick:
            try:
                envelope = self._result_queue.get_nowait()
            except queue.Empty:
                break
            try:
                if envelope.kind == "ui_call":
                    self._apply_ui_call(envelope)
                elif envelope.kind in {"success", "failure"}:
                    self._apply_terminal_result(envelope)
                else:
                    self._break_lane(RuntimeError("unknown lane result envelope"))
            finally:
                self._result_queue.task_done()
            processed += 1
        if self.state != LANE_CLOSED:
            self._schedule_pump()

    def _apply_ui_call(self, envelope: _Envelope) -> None:
        ui_call = envelope.value
        if not isinstance(ui_call, _UiCall):
            self._break_lane(RuntimeError("invalid UI call envelope"))
            return
        try:
            with self._state_lock:
                active = self._active
            if (
                active is None
                or active.op_id != envelope.op_id
                or active.task.generation != envelope.generation
                or not self._generation_is_current(envelope.generation)
            ):
                current_generation = (
                    envelope.generation
                    if self._generation_provider is None
                    else self._generation_provider()
                )
                raise StaleUiCheckpointError(
                    envelope.generation,
                    current_generation,
                )
            ui_call.result = ui_call.callback(*ui_call.args, **ui_call.kwargs)
        except BaseException as exc:
            ui_call.error = exc
        finally:
            ui_call.event.set()

    def _apply_terminal_result(self, envelope: _Envelope) -> None:
        with self._state_lock:
            active = self._active
        if active is None or active.op_id != envelope.op_id or envelope.task is not active.task:
            self._break_lane(RuntimeError("stale or mismatched lane result"))
            return
        try:
            if self._generation_is_current(envelope.generation):
                callback = (
                    active.task.finish
                    if envelope.kind == "success"
                    else active.task.fail
                )
                callback(envelope.value)
            else:
                stale_error = (
                    envelope.value
                    if isinstance(envelope.value, StaleUiGenerationError)
                    else StaleUiResultError(
                        envelope.generation,
                        self._generation_provider(),
                    )
                )
                active.handle.stale_generation_error = stale_error
                if active.task.on_stale is not None:
                    active.task.on_stale()
        except BaseException as exc:
            self._break_lane(exc)
            return

        with self._state_lock:
            draining = self._state == LANE_DRAINING
            self._active = None
            self._state = LANE_DRAINING if draining else LANE_IDLE
            self._idle_barrier = True
        try:
            if active.task.on_idle is not None:
                active.task.on_idle()
        except BaseException as exc:
            self._break_lane(exc)
            return
        finally:
            with self._state_lock:
                self._idle_barrier = False
        if draining:
            self._complete_close()

    def _present_fault(self, exc: BaseException) -> None:
        if self._fault_presented:
            return
        self._fault_presented = True
        if self._on_runner_fault is not None:
            try:
                self._on_runner_fault(exc)
            except BaseException:
                pass

    def _break_lane(self, exc: BaseException) -> None:
        with self._state_lock:
            self._active = None
            self._idle_barrier = False
            self._state = LANE_BROKEN
        self._present_fault(exc)

    def _complete_close(self) -> None:
        self._assert_owner()
        with self._state_lock:
            if self._state == LANE_CLOSED or self._active is not None:
                return
            if not self._stop_sent:
                self._stop_sent = True
                self._task_queue.put_nowait(_STOP)
        self.worker_thread.join(timeout=2.0)
        if self.worker_thread.is_alive():
            self._break_lane(RuntimeError("Tk UI lane worker did not stop"))
            return
        with self._state_lock:
            self._state = LANE_CLOSED
            callbacks = list(self._drain_callbacks)
            self._drain_callbacks.clear()
        pump_job = self._pump_job
        self._pump_job = None
        if pump_job is not None:
            try:
                self._root.after_cancel(pump_job)
            except Exception:
                pass
        for callback in callbacks:
            callback()


class CoalescingTrigger:
    """Coalesce repeated periodic triggers to one active plus one pending."""

    def __init__(self, lane: TkSerialUiLane) -> None:
        self._lane = lane
        self._running = False
        self._pending = False
        self._latest_factory: Callable[[], LaneTask] | None = None

    @property
    def pending_count(self) -> int:
        return 1 if self._pending else 0

    def trigger(self, task_factory: Callable[[], LaneTask]) -> Admission:
        self._lane._assert_owner()
        if self._running or self._lane.is_busy():
            self._pending = True
            self._latest_factory = task_factory
            return Admission(False, reason="busy")
        task = task_factory()
        original_idle = task.on_idle

        def on_idle() -> None:
            if original_idle is not None:
                original_idle()
            self._running = False
            if not self._pending:
                return
            self._pending = False
            pending_factory = self._latest_factory or task_factory
            self._latest_factory = None
            self._lane._root.after(0, self.trigger, pending_factory)

        admission = self._lane.submit(replace(task, on_idle=on_idle))
        self._running = admission.accepted
        return admission


__all__ = [
    "Admission",
    "CoalescingTrigger",
    "DRAIN_TO_DURABLE_HANDOFF",
    "DRAIN_TO_TERMINAL",
    "LaneTask",
    "StaleUiCheckpointError",
    "StaleUiGenerationError",
    "StaleUiResultError",
    "TaskHandle",
    "TkSerialUiLane",
    "UI_LANE_SPEC",
]

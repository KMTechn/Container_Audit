"""A stalled CSV projector keeps durable intake and releases the processing lane."""
import csv
import json
from pathlib import Path
import queue
import threading
import time
from types import SimpleNamespace

import pytest

import Container_Audit as module
from preflight_scan_hold import PreflightScanHoldWriter
from tests.test_container_audit_contracts import _completion_app
from tests.test_tk_serial_ui_lane import FakeTkRoot
from tk_serial_ui_lane import LaneTask, TkSerialUiLane
from writer_session_fence import _WRITER_LOCAL, writer_admission

pytestmark = pytest.mark.usefixtures('owned_tk_workers')


class BoundedQueue(queue.Queue):
    def join(self):
        raise AssertionError('whole-queue join is forbidden')


@pytest.fixture
def log_app(tmp_path):
    app = _completion_app(tmp_path)
    app.log_queue = BoundedQueue()
    app.log_thread = SimpleNamespace(is_alive=lambda: True)
    app._trigger_session_direct_sync = lambda reason: None
    return app


@pytest.fixture
def clock(monkeypatch):
    state = SimpleNamespace(now=0.0, sleeps=[], during_sleep=lambda: None)

    def sleep(seconds):
        assert int(getattr(_WRITER_LOCAL, 'depth', 0)) == 0
        assert 0 < seconds <= .05
        state.sleeps.append(seconds)
        state.now += seconds
        state.during_sleep()

    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: state.now, sleep=sleep))
    return state


def csv_rows(app):
    with open(app.log_file_path, encoding='utf-8-sig', newline='') as handle:
        return list(csv.DictReader(handle))


def later_projection(app):
    app.log_thread = threading.Thread(target=app._event_log_writer, name='test-late-csv-projector')
    app.log_thread.start()
    try:
        app.log_queue.put(None)
        app.log_thread.join(timeout=5)
        assert not app.log_thread.is_alive()
        assert app.log_queue.unfinished_tasks == 0
    finally:
        if app.log_thread.is_alive():
            app.log_thread.join(timeout=5)


@pytest.mark.parametrize('writer_state', ['dead', 'slow'])
def test_stalled_log_wait_keeps_original_and_allows_next_lane_work(log_app, clock, writer_state, capsys):
    app = log_app
    app.log_thread = SimpleNamespace(is_alive=lambda: writer_state == 'slow')
    app.log_queue.put({})
    root = FakeTkRoot()
    lane = TkSerialUiLane(root)
    results = []

    def log():
        accepted = app._log_event('WORK_PAUSE', detail={'message': 'fixture pause'}, synchronous=True)
        return accepted, app._last_log_event_projection_pending, app._last_log_event_was_replay

    try:
        assert lane.submit(LaneTask('bounded-csv', 0, log, results.append, lambda error: pytest.fail(type(error).__name__))).accepted
        root.run_until(lambda: len(results) == 1 and not lane.is_busy(), timeout=5)
        assert lane.submit(LaneTask('next-save', 0, app._save_current_tray_state, results.append,
                                    lambda error: pytest.fail(type(error).__name__))).accepted
        root.run_until(lambda: len(results) == 2, timeout=5)
        assert results == [(True, True, False), True]
        assert Path(app.save_folder, app.CURRENT_TRAY_STATE_FILE).is_file()
        if writer_state == 'dead':
            assert not clock.sleeps and clock.now == 0
        else:
            assert clock.now == pytest.approx(app.LOOP_CLEANUP_TIMEOUT_SECONDS)
        assert 'EVENT_CSV_PROJECTION_PENDING' in capsys.readouterr().out
        assert app._event_log_notice
        assert not Path(app.log_file_path).exists()
        originals = list(app._event_log_outbox_instance.directory.glob('*.json'))
        assert len(originals) == 1
        original = json.loads(originals[0].read_text(encoding='utf-8'))['log_entry']
        later_projection(app)
        assert csv_rows(app) == [original]
        assert not list(app._event_log_outbox_instance.directory.glob('*.json'))
    finally:
        lane.drain_then(lambda: None)
        root.run_until(lambda: lane.state == 'CLOSED', timeout=5)
        assert not lane.worker_thread.is_alive()


@pytest.mark.parametrize('queued', [False, True])
def test_healthy_projector_still_completes_synchronous_csv(log_app, clock, queued):
    app = log_app
    if queued:
        app.log_queue.put({})

        def finish_prior_row():
            app.log_queue.get_nowait()
            app.log_queue.task_done()

        clock.during_sleep = finish_prior_row
    assert app._log_event('WORK_PAUSE', detail={'message': 'fixture pause'}, synchronous=True)
    assert not app._last_log_event_projection_pending
    assert not app._last_log_event_was_replay
    assert len(csv_rows(app)) == 1
    assert clock.now == (.05 if queued else 0)
    assert not list(app._event_log_outbox_instance.directory.glob('*.json'))


@pytest.mark.parametrize('writer_state', ['dead', 'slow'])
@pytest.mark.parametrize('event', ['TRAY_COMPLETE', 'PRODUCT_EXCHANGE_COMPLETED', 'PHS_REPLACEMENT_WAITING_MARKED'])
@pytest.mark.parametrize('local_only', [False, True])
def test_deferred_contract_event_wakes_sync_after_later_csv_without_periodic_wait(log_app, clock, monkeypatch, writer_state, event, local_only):
    app = log_app
    app.log_thread = SimpleNamespace(is_alive=lambda: writer_state == 'slow')
    app.current_tray.is_test_tray = local_only
    app.log_queue.put({})
    payload = app._prepare_event_log_entry(event, {'message': 'fixture delayed CSV'}, worker_record=app._worker_record_context())
    sent, flushes = [], []

    def send_after_csv(reason):
        assert int(getattr(_WRITER_LOCAL, 'depth', 0)) == 0
        with open(payload['log_file_path'], encoding='utf-8-sig', newline='') as handle:
            assert list(csv.DictReader(handle)) == [payload['log_entry']]
        assert not list(app._event_log_outbox_instance.directory.glob('*.json'))
        sent.append((reason, len(flushes)))

    monkeypatch.setattr(app, '_trigger_session_direct_sync', send_after_csv)
    assert app._write_event_log_entry(payload, synchronous=True)
    assert app._last_log_event_projection_pending and not sent
    assert not Path(payload['log_file_path']).exists()
    queued = list(app.log_queue.queue)[-1]
    assert queued.get('direct_sync_event') == (None if local_only else event)
    drain = app._flush_pending_event_logs

    def retry_projection():
        flushes.append(True)
        return False if len(flushes) <= 3 else drain()

    monkeypatch.setattr(app, '_flush_pending_event_logs', retry_projection)
    later_projection(app)
    assert len(flushes) == 4
    assert sent == ([] if local_only else [(event, 4)])
    with open(payload['log_file_path'], encoding='utf-8-sig', newline='') as handle:
        assert list(csv.DictReader(handle)) == [payload['log_entry']]


def test_later_projection_retains_each_pending_sync_reason(log_app, clock, monkeypatch):
    app = log_app
    app.log_thread = SimpleNamespace(is_alive=lambda: False)
    app.log_queue.put({})
    payloads = [app._prepare_event_log_entry(event, {'message': 'fixture batch'}, worker_record=app._worker_record_context())
                for event in ('TRAY_COMPLETE', 'PHS_REPLACEMENT_WAITING_MARKED')]
    sent, flushes = [], []
    for payload in payloads:
        assert app._write_event_log_entry(payload, synchronous=True)
    drain = app._flush_pending_event_logs

    def retry_projection():
        flushes.append(True)
        return False if len(flushes) <= 4 else drain()

    def send_after_csv(reason):
        assert csv_rows(app) == [payload['log_entry'] for payload in payloads]
        sent.append((reason, len(flushes)))

    monkeypatch.setattr(app, '_flush_pending_event_logs', retry_projection)
    monkeypatch.setattr(app, '_trigger_session_direct_sync', send_after_csv)
    later_projection(app)
    assert sorted(sent) == [('PHS_REPLACEMENT_WAITING_MARKED', 5), ('TRAY_COMPLETE', 5)]


def test_scan_ack_does_not_wait_for_unrelated_dead_log_queue(log_app, clock):
    app = log_app
    app.log_thread = SimpleNamespace(is_alive=lambda: False)
    app.log_queue.put({})
    assert app._log_event('SCAN_OK', detail={'barcode': 'fixture scan'}, synchronous=True)
    assert not app._last_log_event_projection_pending
    assert not clock.sleeps and len(csv_rows(app)) == 1
    app.log_queue.get_nowait()
    app.log_queue.task_done()


def test_nested_writer_defers_projection_without_waiting(log_app, clock):
    app = log_app
    app.log_queue.put({})
    with writer_admission('event_outbox_stage'):
        assert app._log_event('WORK_PAUSE', detail={'message': 'fixture pause'}, synchronous=True)
    assert app._last_log_event_projection_pending and not clock.sleeps
    assert not Path(app.log_file_path).exists()
    later_projection(app)
    assert len(csv_rows(app)) == 1


@pytest.mark.parametrize('close_via_pump', [False, True])
def test_hold_writer_retries_join_and_sends_stop_once(close_via_pump):
    root = FakeTkRoot()
    writer = PreflightScanHoldWriter(root, queue_capacity=2)
    actual_thread = writer.thread
    joins, finished, drained = [], [], []

    class SlowJoin:
        def join(self, timeout):
            joins.append(timeout)
            actual_thread.join(timeout=timeout)

        def is_alive(self):
            return len(joins) == 1 or actual_thread.is_alive()

    writer.thread = SlowJoin()
    try:
        if close_via_pump:
            assert writer.submit(lambda: 'saved', finished.append, lambda error: pytest.fail(type(error).__name__)).accepted
            deadline = time.monotonic() + 2
            while writer.results.empty():
                assert time.monotonic() < deadline
                threading.Event().wait(.002)
        writer.drain_then(lambda: drained.append(True))
        if close_via_pump:
            root.run_one()
            assert finished == ['saved']
        assert not writer._closed and not drained and joins == [2.0]
        root.run_until(lambda: writer._closed, timeout=3)
        assert joins == [2.0, 2.0] and drained == [True]
        assert writer.tasks.unfinished_tasks == 0 and writer.results.empty()
        assert writer.close_idle() and drained == [True]
    finally:
        writer.thread = actual_thread
        writer.close_idle()
        assert not actual_thread.is_alive()

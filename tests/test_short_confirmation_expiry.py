"""DESIGN 11-13: the last short tray reaches transport without another scan."""
import datetime
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest
import Container_Audit as ca
from tests.test_w9scanonly_workflow import (
    _active, flow, windows, fixed_operation_lease_clock,  # noqa: F401
    COMPACT_QR, OTHER_LABEL, ITEM, _rows,
)
from tests.test_phs2_master_preflight import ScheduledRoot

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


@pytest.fixture
def clock(monkeypatch):
    base = ca.datetime.datetime.now()
    value = SimpleNamespace(seconds=0.0, wall_offset=0.0)

    class ClockDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            result = base + datetime.timedelta(seconds=value.seconds + value.wall_offset)
            return result if tz is None else result.replace(tzinfo=tz)

    dates = SimpleNamespace(**vars(ca.datetime))
    dates.datetime = ClockDateTime
    times = SimpleNamespace(**vars(ca.time))
    times.monotonic = lambda: value.seconds
    monkeypatch.setattr(ca, 'datetime', dates)
    monkeypatch.setattr(ca, 'time', times)
    return value


class TimedRoot(ScheduledRoot):
    """Run Tk callbacks only when their requested delay has elapsed."""
    def __init__(self, clock):
        super().__init__()
        self.clock = clock
        self.due = {}
        self.serial = 0

    def winfo_exists(self):
        return True

    def after(self, delay, callback, *args):
        self.serial += 1
        job = f'timed-{self.serial}'
        self.jobs.append((job, delay, callback, args))
        self.due[id(self.jobs[-1])] = self.clock.seconds + delay / 1000
        return job

    def run_next(self):
        for entry in list(self.jobs):
            if self.due[id(entry)] <= self.clock.seconds:
                self.jobs.remove(entry)
                if entry[0] not in self.cancelled:
                    entry[2](*entry[3])
                return

    def tick(self):
        # Future jobs stay queued, as they do in Tk; lane callbacks can arrive later.
        for _ in range(100):
            if not any(self.due[id(entry)] <= self.clock.seconds for entry in self.jobs):
                break
            self.run_next()


def hold(flow, monkeypatch, clock, *, transition=False, root=None):
    app = (flow(transition=True, root=root) if transition else
           _active(lambda **kwargs: flow(root=root, **kwargs)))
    app.root = TimedRoot(clock)
    app.log_file_path = str(Path(app.save_folder) / f'이적작업이벤트로그_tester_{ca.datetime.date.today():%Y%m%d}.csv')
    sent = []

    def transport(*, lookup=None):
        if lookup is not None:
            return True
        # Synthetic central consumer observes only the real durable READY intents.
        store = app.transfer_seal_coordinator.store
        sent.extend(store.pending_ids())
        return True

    monkeypatch.setattr(app, '_schedule_scanonly_transport', transport)
    if transition:
        app._process_barcode_logic(f'CLC={ITEM}|QT=3')
    app._process_barcode_logic(ITEM + '-SERIAL-001')
    if transition:
        assert app._complete_current_tray_as_partial()
    else:
        app._process_barcode_logic(COMPACT_QR)
    undo = app._short_confirmation_undo
    path = app._short_projection_path(undo['completion_id'])
    return app, sent, path, dict(undo)


def test_33_seconds_keeps_undo_and_no_central_completion(flow, windows, monkeypatch, clock):
    app, sent, path, undo = hold(flow, monkeypatch, clock)
    clock.seconds = 33
    app.root.tick()
    assert app._short_confirmation_undo == undo
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'HELD'
    assert _rows(app, 'TRAY_COMPLETE') == [] and sent == []
    assert app._undo_short_confirmation()
    clock.seconds = 61
    app.root.tick()
    assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'CANCELLED'
    assert sent == [] and windows == []


@pytest.mark.parametrize('transition', [False, True])
def test_61_seconds_settles_once_without_next_scan(flow, windows, monkeypatch, clock, transition):
    app, sent, path, undo = hold(flow, monkeypatch, clock, transition=transition)
    clock.seconds = 61
    app.root.tick()
    assert app._short_confirmation_undo is None
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'SETTLED'
    rows = _rows(app, 'TRAY_COMPLETE')
    assert len(rows) == 1
    assert rows[0]['timestamp'] == json.loads(path.read_text(encoding='utf-8'))['contract']['observed_at']
    assert sent == ([] if transition else [undo['intent_id']])
    clock.seconds = 180
    app.root.tick()
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert sent == ([] if transition else [undo['intent_id']])
    assert windows == []


@pytest.mark.parametrize('wall_offset', [-3600, 3600])
def test_running_grace_uses_durable_confirmation_clock(flow, windows, monkeypatch, clock, wall_offset):
    # sub-419 / DESIGN 11-13: sleep must count and clock rollback must defer.
    app, sent, path, undo = hold(flow, monkeypatch, clock)
    clock.wall_offset = wall_offset
    clock.seconds = 33
    app.root.tick()
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == ('HELD' if wall_offset < 0 else 'SETTLED')
    clock.seconds = 61
    app.root.tick()
    if wall_offset < 0:
        assert sent == []
        assert len(_rows(app, 'SHORT_CONFIRMATION_CLOCK_REGRESSION')) == 1
        clock.wall_offset = 0
        clock.seconds = 62
        app.root.tick()
    assert sent == [undo['intent_id']]
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1 and windows == []


@pytest.mark.parametrize('elapsed', [30, 70])
def test_resume_clock_tick_counts_sleep_without_another_scan(flow, windows, monkeypatch, clock, elapsed):
    app, sent, path, undo = hold(flow, monkeypatch, clock)
    confirmed_contract = json.loads(path.read_text(encoding='utf-8'))['contract']
    clock.wall_offset = elapsed  # Sleep advances wall time while timers are suspended.
    app._update_clock()
    app.root.tick()
    if elapsed < 60:
        assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'HELD'
        assert sent == []
        clock.seconds = 29
        app.root.tick()
        assert sent == []
        clock.seconds = 30  # The boundary is >=60 seconds, including at exactly 60.
        app._update_clock()
        app.root.tick()
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'SETTLED'
    assert app._short_confirmation_undo is None
    assert sent == [undo['intent_id']]
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert json.loads(path.read_text(encoding='utf-8'))['contract'] == confirmed_contract
    clock.seconds = 180
    app.root.tick()
    assert sent == [undo['intent_id']] and windows == []


def test_delayed_expiry_callback_counts_sleep(flow, windows, monkeypatch, clock):
    app, sent, path, undo = hold(flow, monkeypatch, clock)
    callback = next(entry[2] for entry in app.root.jobs if entry[0] == app._short_confirmation_expiry_job)
    clock.wall_offset = 70
    callback()
    app.root.tick()
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'SETTLED'
    assert sent == [undo['intent_id']]
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1 and windows == []


@pytest.mark.parametrize('busy', [False, True])
def test_resume_undo_after_expiry_is_refused_before_delayed_timer(flow, windows, monkeypatch, clock, busy):
    app, sent, path, undo = hold(flow, monkeypatch, clock)
    errors = []
    monkeypatch.setattr(app, '_start_warning_beep', lambda: errors.append('error'))
    app._scan_callback_pending = busy
    clock.wall_offset = 70
    assert app._undo_short_confirmation() is False
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == ('HELD' if busy else 'SETTLED')
    assert any('미달 확정 취소 시간이 지났습니다' in notice[0] for notice in app.statuses)
    assert errors == ['error']
    app._scan_callback_pending = False
    app._update_clock()
    app.root.tick()
    assert sent == [undo['intent_id']]
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1 and windows == []


def test_backward_clock_after_sleep_defers_and_records_once(flow, windows, monkeypatch, clock):
    app, sent, path, undo = hold(flow, monkeypatch, clock)
    clock.wall_offset = 50
    app._update_clock()
    clock.wall_offset = 40
    app._update_clock()
    app._update_clock()
    app.root.tick()
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'HELD' and sent == []
    assert len(_rows(app, 'SHORT_CONFIRMATION_CLOCK_REGRESSION')) == 1
    clock.wall_offset = 70
    app._update_clock()
    app.root.tick()
    assert sent == [undo['intent_id']] and windows == []


@pytest.mark.parametrize('elapsed', [33, 61])
@pytest.mark.parametrize('transition', [False, True])
def test_restart_keeps_remaining_grace_or_settles_expired(flow, windows, monkeypatch, clock, tmp_path, elapsed, transition):
    root = tmp_path / 'restart'
    app, _, path, undo = hold(flow, monkeypatch, clock, transition=transition, root=root)
    # Crash between durable projection and current-checkpoint cleanup.
    state = json.loads(path.read_text(encoding='utf-8'))['state']
    assert app._save_tray_state_snapshot(state)
    clock.seconds = elapsed
    restarted = flow(transition=transition, root=root)
    restarted.root = TimedRoot(clock)
    monkeypatch.setattr(restarted, '_schedule_scanonly_transport', lambda: True)
    restarted._restore_tray_from_state(state)
    result = restarted._recover_short_completion_projections(restarted.transfer_seal_coordinator)
    restarted._apply_short_projection_recovery(result)
    if elapsed < 60:
        assert _rows(restarted, 'TRAY_COMPLETE') == []
        assert restarted._short_confirmation_undo['completion_id'] == undo['completion_id']
        clock.seconds = 59
        restarted.root.tick()
        assert _rows(restarted, 'TRAY_COMPLETE') == []
        clock.seconds = 61
        restarted.root.tick()
    assert restarted.current_tray.master_label_code == ''
    assert len(_rows(restarted, 'TRAY_COMPLETE')) == 1
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'SETTLED'
    if not transition:
        assert restarted.transfer_seal_coordinator.store.pending_ids() == [undo['intent_id']]
    assert windows == []


def test_expiry_waits_for_scan_and_retries_lost_csv_ack(flow, windows, monkeypatch, clock):
    app, sent, path, undo = hold(flow, monkeypatch, clock)
    app._scan_callback_pending = True
    clock.seconds = 61
    app.root.tick()
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'HELD'
    assert sent == []
    app._scan_callback_pending = False
    original = app._log_stored_event
    lost = [True]

    def append_with_lost_ack(*args, **kwargs):
        result = original(*args, **kwargs)
        if lost[0]:
            lost[0] = False
            return False
        return result

    monkeypatch.setattr(app, '_log_stored_event', append_with_lost_ack)
    clock.seconds = 62
    app.root.tick()
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'SETTLING'
    assert sent == []
    assert not app._undo_short_confirmation()
    clock.seconds = 64
    app.root.tick()
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert sent == [undo['intent_id']]
    assert windows == []


def test_restored_grace_can_be_undone_and_old_callback_cannot_settle(flow, windows, monkeypatch, clock, tmp_path):
    root = tmp_path / 'undo-restart'
    app, _, path, undo = hold(flow, monkeypatch, clock, transition=True, root=root)
    clock.seconds = 33
    restarted = flow(transition=True, root=root)
    restarted.root = TimedRoot(clock)
    sent = []
    monkeypatch.setattr(restarted, '_schedule_scanonly_transport', lambda: sent.append(True))
    restarted._apply_short_projection_recovery(
        restarted._recover_short_completion_projections(restarted.transfer_seal_coordinator))
    assert restarted._short_confirmation_undo['completion_id'] == undo['completion_id']
    callback = next(entry[2] for entry in restarted.root.jobs if entry[0] == restarted._short_confirmation_expiry_job)
    assert restarted._undo_short_confirmation()
    clock.seconds = 61
    callback()  # A callback already dequeued by Tk can outlive after_cancel.
    restarted.root.tick()
    assert restarted.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'CANCELLED'
    assert sent == [] and windows == []


@pytest.mark.parametrize('boundary', ['label', 'worker', 'close'])
def test_existing_boundary_settles_before_60_seconds(flow, windows, monkeypatch, clock, boundary):
    app, sent, path, undo = hold(flow, monkeypatch, clock)
    clock.seconds = 33
    resumed = []
    if boundary == 'label':
        app._process_barcode_logic(OTHER_LABEL + '|QT=1')
    elif boundary == 'worker':
        entry = app.change_worker
        monkeypatch.setattr(app, 'change_worker', lambda **kwargs: resumed.append(kwargs))
        entry()
    else:
        entry = app.on_closing
        monkeypatch.setattr(app, 'on_closing', lambda **kwargs: resumed.append(kwargs))
        entry()
    # The real worker/close entry points settle on the persistence lane before resuming.
    deadline = time.monotonic() + 15
    while (app._short_confirmation_undo is not None or
           (getattr(app, '_ui_lane', None) is not None and app._ui_lane.is_busy())) and time.monotonic() < deadline:
        clock.seconds += .1
        app.root.tick()
        time.sleep(.005)
    app.root.tick()
    assert app._short_confirmation_undo is None
    assert json.loads(path.read_text(encoding='utf-8'))['status'] == 'SETTLED'
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1
    assert sent == [undo['intent_id']]
    if boundary == 'worker':
        assert resumed == [{'_short_settled': True, '_confirmed': False}]
    elif boundary == 'close':
        assert resumed == [{'_confirmed': True}]
    else:
        assert app.current_tray.master_label_code == OTHER_LABEL + '|QT=1'
    clock.seconds = 180
    app.root.tick()
    assert len(_rows(app, 'TRAY_COMPLETE')) == 1 and sent == [undo['intent_id']]
    assert windows == []

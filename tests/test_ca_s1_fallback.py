"""Verify M84 exit and manual next-start behavior without native windows."""
import builtins
from contextlib import contextmanager
import sys
import threading
from types import MethodType, SimpleNamespace

import pytest
import Container_Audit as ca
import ca_screen_bridge as screen
import writer_session_fence as fence
from tests.test_ca_new_screen_entry import entry, _SurfaceEvent


@pytest.fixture
def visible(entry, monkeypatch):
    state = SimpleNamespace(tk=0, web=0, preparations=[])
    prepare = ca._prepare_gui_startup
    def preparing(**kwargs):
        state.tk = 0 if ca.CA_SCREEN_HOST['active'] else 1
        state.preparations.append(state.tk)
        assert state.tk + state.web <= 1
        return prepare(**kwargs)
    monkeypatch.setattr(ca, '_prepare_gui_startup', preparing)
    yield state
    assert state.tk + state.web <= 1


@pytest.mark.parametrize('failure', ('SHELL_START_FAILED', 'SHELL_START_TIMEOUT'))
def test_created_web_failure_with_fallback_marker_exits_then_manual_start_opens_one_tk(entry, visible, monkeypatch, failure):
    marker, order = [], []
    entry.bridge._startup_failure = failure
    entry.bridge.pump = lambda: False
    entry.bridge.attach_owner = lambda processor: None
    entry.app._loop_cleanup_finished = False
    def loop():
        next(callback for delay, callback in reversed(entry.callbacks) if delay == 10)()
    def cleanup():
        order.append('owner_cleanup')
        entry.app._loop_cleanup_finished = True
        entry.app._application_close_complete = True
    entry.app.root.mainloop = loop
    entry.app._cleanup_after_mainloop = cleanup
    entry.app.run = MethodType(ca.ContainerAudit.run, entry.app)
    monkeypatch.setattr(fence, 'close_and_wait_writers', lambda deadline: order.append('writes_empty') or True)
    webview = sys.modules['webview']
    def create():
        window = SimpleNamespace(events=SimpleNamespace(shown=_SurfaceEvent()))
        webview.windows.append(window)
        visible.web = 1
        assert visible.tk + visible.web == 1
        return window
    webview.create_window = create
    def run_app(profile, data, **kwargs):
        assert 'on_fallback' not in kwargs
        webview.create_window()
        kwargs['owner_main'](entry.bridge)
        assert visible.preparations == [0] and 'deiconify' not in entry.events
        assert order.count('owner_cleanup') == 1 and entry.releases == [True]
        marker.append(ca.CURRENT_VERSION)
        order.append('marker')
        webview.windows.clear()
        visible.web = 0
        order.append('destroy')
        assert kwargs['before_exit'](failure, 120) is True
        order.append('exit_3')
        assert visible.tk + visible.web == 0
        raise SystemExit(3)
    def web_allowed(data, version, *, write_guard):
        assert write_guard is screen.admission_write_guard
        return version not in marker
    fake = SimpleNamespace(run_app=run_app, web_allowed=web_allowed)
    monkeypatch.setitem(sys.modules, 'host', fake)
    with pytest.raises(SystemExit) as ended:
        ca.main([])
    assert ended.value.code == 3 and order.count('exit_3') == 1
    assert order.index('destroy') < order.index('writes_empty') < order.index('exit_3')
    def tk_loop():
        assert fence._WRITER_EXIT_COUNT == 0
    entry.app.run = tk_loop
    assert ca.main([]) == 0
    assert visible.preparations == [0, 1] and visible.tk + visible.web == 1
    assert entry.gate_arguments == []
    assert len(entry.releases) == 2 and not webview.windows


def test_hung_exit_defers_until_writer_mutex_is_released(entry, visible, monkeypatch):
    entered, finish, released = threading.Event(), threading.Event(), threading.Event()
    monkeypatch.setattr(fence, '_WRITER_EXIT_CLOSED', False)
    @contextmanager
    def admitted(*args, **kwargs):
        business_writer = threading.current_thread() is thread
        if business_writer:
            entered.set()
        try:
            yield
        finally:
            if business_writer:
                released.set()
    monkeypatch.setattr(fence, '_writer_admission', admitted)
    def writing():
        with fence.writer_admission('synthetic'):
            assert finish.wait(5)
    thread = threading.Thread(target=writing)
    thread.start()
    order = []
    def run_app(profile, data, **kwargs):
        assert entered.wait(5)
        assert kwargs['before_exit']('SHELL_START_HUNG', 0) is False
        assert not released.is_set() and not entry.releases
        order.append('SHELL_EXIT_DEFERRED')
        with pytest.raises(fence.WriterFencedError) as refused:
            with fence.writer_admission('new'):
                pytest.fail('New write was admitted')
        assert refused.value.code == 'WRITER_EXIT_CLOSED'
        assert 'prepare' not in entry.events
        finish.set()
        thread.join(5)
        assert not thread.is_alive() and released.is_set()
        assert kwargs['before_exit']('SHELL_START_HUNG', 0) is True
        order.append('exit_3')
        raise SystemExit(3)
    monkeypatch.setitem(sys.modules, 'host', SimpleNamespace(run_app=run_app))
    try:
        with pytest.raises(SystemExit) as ended:
            ca.main([])
        assert ended.value.code == 3
    finally:
        finish.set()
        thread.join(5)
    assert order == ['SHELL_EXIT_DEFERRED', 'exit_3']
    assert visible.tk + visible.web == 0 and 'deiconify' not in entry.events


@pytest.mark.parametrize('module_name', ('ca_screen_bridge', 'host', 'webview'))
def test_shell_import_failure_records_code_and_opens_one_tk(entry, visible, monkeypatch, module_name):
    original = builtins.__import__
    recorded = []
    def guarded(name, *args, **kwargs):
        if name == module_name:
            raise ImportError('Synthetic unavailable shell')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    monkeypatch.setattr(ca, '_startup_check_observe', lambda action, *args, **kwargs: recorded.extend(args) if action == 'note' else False)
    assert ca.main([]) == 0
    assert recorded == ['SHELL_IMPORT_FAILED']
    assert visible.tk + visible.web == 1 and len(entry.releases) == 1


@pytest.mark.parametrize('arguments', (['--old-screen'], ['--ui', 'tk'], ['--ui=tk']))
def test_emergency_routes_leave_shell_modules_unimported(entry, visible, monkeypatch, arguments):
    shell_modules = {'host', 'webview', 'ca_screen_bridge', 'clr_loader', 'pythonnet'}
    for name in shell_modules:
        monkeypatch.delitem(sys.modules, name, raising=False)
    original = builtins.__import__
    imported = []
    def guarded(name, *args, **kwargs):
        if name.split('.')[0] in shell_modules:
            imported.append(name)
            raise ImportError('Synthetic unavailable shell')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    assert ca.main(arguments) == 0
    assert imported == [] and shell_modules.isdisjoint(sys.modules)
    assert visible.tk + visible.web == 1 and len(entry.releases) == 1






def test_exit_waits_for_writer_mutex_even_without_a_local_admission(entry, visible, monkeypatch):
    monkeypatch.setattr(fence, '_WRITER_EXIT_CLOSED', False)
    held, finish = threading.Event(), threading.Event()
    failures = []
    name = fence.writer_admission_mutex_name(fence.canonical_control_root())
    def holding():
        mutex = None
        try:
            mutex = fence._acquire_named_mutex(name, 1)
            assert mutex is not None
            held.set()
            assert finish.wait(5)
        except BaseException as error:
            failures.append(error)
            held.set()
        finally:
            if mutex is not None:
                mutex.release()
    writer = threading.Thread(target=holding)
    writer.start()
    def run_app(profile, data, **kwargs):
        assert held.wait(5) and not failures
        assert fence._WRITER_EXIT_COUNT == 0
        assert kwargs['before_exit']('SHELL_START_TIMEOUT', 0) is False
        finish.set()
        writer.join(5)
        assert not writer.is_alive() and not failures
        assert kwargs['before_exit']('SHELL_START_TIMEOUT', 0) is True
        assert 'prepare' not in entry.events
        raise SystemExit(3)
    monkeypatch.setitem(sys.modules, 'host', SimpleNamespace(run_app=run_app))
    try:
        with pytest.raises(SystemExit):
            ca.main([])
    finally:
        finish.set()
        writer.join(5)
    assert visible.tk + visible.web == 0


@pytest.mark.parametrize('worker_kind', ('ui', 'transport', 'hold', 'broken'))
def test_exit_requires_every_lane_worker_to_be_dead(entry, monkeypatch, worker_kind):
    from tk_serial_ui_lane import TkSerialUiLane
    from preflight_scan_hold import PreflightScanHoldWriter
    monkeypatch.setattr(fence, '_WRITER_EXIT_CLOSED', False)
    if worker_kind == 'hold':
        lane = PreflightScanHoldWriter(entry.app.root, queue_capacity=2)
        worker = lane.thread
        close = lane.close_idle
    else:
        lane = TkSerialUiLane(entry.app.root)
        worker = lane.worker_thread
        close = lane.close_idle
        if worker_kind == 'broken':
            lane.mark_broken(RuntimeError('Synthetic broken lane'))
    closed = []
    def run_app(profile, data, **kwargs):
        assert worker.is_alive() and fence._WRITER_EXIT_COUNT == 0
        assert kwargs['before_exit']('SHELL_START_HUNG', 0) is False
        assert worker.is_alive() and not entry.releases and not closed
        close()
        closed.append(True)
        assert not worker.is_alive()
        assert kwargs['before_exit']('SHELL_START_HUNG', 0) is True
        raise SystemExit(3)
    monkeypatch.setitem(sys.modules, 'host', SimpleNamespace(run_app=run_app))
    try:
        with pytest.raises(SystemExit):
            ca.main([])
    finally:
        close()
    assert closed == [True]


def test_entry_and_packet_have_no_automatic_restart_wait():
    from pathlib import Path
    from tools import build_portable_release_candidate as builder
    root = Path(ca.__file__).parent
    for path in (root / 'Container_Audit.py', root / 'portable/main.py'):
        text = path.read_text(encoding='utf-8')
        for removed in ('relaunch_wait', 'wait_previous_from_argv', '--after-pid'):
            assert removed not in text
    assert not (root / 'relaunch_wait.py').exists()
    assert 'relaunch_wait.py' not in builder.APP_ROOT_FILES
    assert fence.EXIT_WRITE_WAIT_S == 120 and fence.EXIT_POLL_S == 5


def test_failed_fallback_mark_exits_without_automatic_retry(entry, visible, monkeypatch):
    import subprocess
    records = []
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('Unexpected automatic process start'))
    monkeypatch.setattr(fence, 'close_and_wait_writers', lambda timeout: True)
    webview = sys.modules['webview']
    def run_app(profile, data, **kwargs):
        webview.windows.append(SimpleNamespace(events=SimpleNamespace(shown=_SurfaceEvent())))
        visible.web = 1
        kwargs['owner_main'](entry.bridge)
        records.append('SHELL_FALLBACK_MARK_FAILED')
        webview.windows.clear()
        visible.web = 0
        assert kwargs['before_exit']('SHELL_START_FAILED', 120) is True
        assert visible.tk + visible.web == 0
        raise SystemExit(3)
    monkeypatch.setitem(sys.modules, 'host', SimpleNamespace(run_app=run_app))
    with pytest.raises(SystemExit) as ended:
        ca.main([])
    assert ended.value.code == 3 and records == ['SHELL_FALLBACK_MARK_FAILED']
    assert visible.preparations == [0] and visible.tk + visible.web == 0

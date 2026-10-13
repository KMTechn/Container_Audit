"""Verify the M83 relaunch adapter with no native windows or process exits."""
import ast
import builtins
from contextlib import contextmanager
from pathlib import Path
import sys
import threading
from types import MethodType, SimpleNamespace

import pytest
import Container_Audit as ca
import relaunch_wait
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
def test_created_web_failure_relaunches_once_then_waits_and_opens_one_tk(entry, visible, monkeypatch, failure):
    marker, order = [], []
    old_ended = threading.Event()
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
        order.extend(('relaunch_self', 'exit_3'))
        assert visible.tk + visible.web == 0
        raise SystemExit(3)
    fake = SimpleNamespace(run_app=run_app, web_allowed=lambda data, version: version not in marker)
    monkeypatch.setitem(sys.modules, 'host', fake)
    with pytest.raises(SystemExit) as ended:
        ca.main([])
    assert ended.value.code == 3 and order.count('relaunch_self') == 1
    assert order.index('destroy') < order.index('writes_empty') < order.index('relaunch_self')
    old_ended.set()
    def wait(pid, timeout):
        order.append('previous_ended')
        return old_ended.is_set()
    monkeypatch.setattr(relaunch_wait, '_wait_for_previous_process', wait)
    def tk_loop():
        assert fence._WRITER_EXIT_COUNT == 0
    entry.app.run = tk_loop
    assert ca.main(['--after-pid', '123']) == 0
    assert visible.preparations == [0, 1] and visible.tk + visible.web == 1
    assert entry.gate_arguments == [] and order.count('previous_ended') == 1
    assert len(entry.releases) == 2 and not webview.windows


def test_hung_exit_defers_until_writer_mutex_is_released(entry, visible, monkeypatch):
    entered, finish, released = threading.Event(), threading.Event(), threading.Event()
    monkeypatch.setattr(fence, '_WRITER_EXIT_CLOSED', False)
    @contextmanager
    def admitted(*args, **kwargs):
        entered.set()
        try:
            yield
        finally:
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
        order.extend(('relaunch_self', 'exit_3'))
        raise SystemExit(3)
    monkeypatch.setitem(sys.modules, 'host', SimpleNamespace(run_app=run_app))
    try:
        with pytest.raises(SystemExit) as ended:
            ca.main([])
        assert ended.value.code == 3
    finally:
        finish.set()
        thread.join(5)
    assert order == ['SHELL_EXIT_DEFERRED', 'relaunch_self', 'exit_3']
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


def test_previous_pid_wait_precedes_guards_and_timeout_opens_no_app(entry, visible, monkeypatch):
    monkeypatch.setattr(relaunch_wait, '_wait_for_previous_process', lambda pid, timeout: False)
    assert ca.main(['--after-pid', '123']) == 1
    assert entry.events == [] and not entry.releases and not entry.host_calls
    assert visible.tk + visible.web == 0


def test_relaunch_wait_has_only_standard_library_dependencies():
    tree = ast.parse(Path(relaunch_wait.__file__).read_text(encoding='utf-8'))
    names = {node.module if isinstance(node, ast.ImportFrom) else alias.name
             for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
             for alias in (node.names if isinstance(node, ast.Import) else [None])}
    assert names <= sys.stdlib_module_names
    main = next(node for node in ast.parse(Path(ca.__file__).read_text(encoding='utf-8')).body
                if isinstance(node, ast.FunctionDef) and node.name == 'main')
    assert isinstance(main.body[0], ast.ImportFrom) and main.body[0].module == 'relaunch_wait'


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

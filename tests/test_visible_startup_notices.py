"""Startup error owners and advisory banners, without real Tk windows."""
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
from tests.test_startup_catalog_notice import (
    startup, flow, fixed_operation_lease_clock, _offline_catalog,
    public_scan, COMPACT_QR, ITEM,
)


WARNING = '이 PC의 설치 기록 일부가 없습니다 — 작업은 계속할 수 있습니다 · 현장 관리자에게 알리세요'
pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


class Widget:
    def __init__(self, root, **options):
        self.root, self.options = root, options

    def pack(self, **_options):
        return self

    def focus_set(self):
        self.root.events.append('button-focus')

    def invoke(self):
        self.options['command']()


class Root:
    def __init__(self, fake, parent=None, hidden=False):
        self.fake, self.parent, self.hidden = fake, parent, hidden
        self.events, self.bindings, self.jobs = [], {}, {}
        self.destroyed = False
        fake.roots.append(self)

    def title(self, title):
        self.caption = title

    def resizable(self, *_args):
        pass

    def transient(self, parent):
        assert parent is self.parent and not parent.hidden
        assert 'deiconify' in parent.events and 'lift' in parent.events
        self.events.append('transient')

    def deiconify(self):
        if not self.hidden:
            self.events.append('deiconify')

    def lift(self):
        if not self.hidden:
            self.events.append('lift')

    def attributes(self, name, value):
        self.events.append((name, value))

    def focus_force(self):
        if not self.hidden:
            self.events.append('focus')

    def update_idletasks(self):
        pass

    def update(self):
        self.events.append('update')

    def bind(self, key, callback):
        self.bindings[key] = callback

    def protocol(self, key, callback):
        self.bindings[key] = callback

    def after(self, delay, callback):
        job = len(self.jobs) + 1
        self.jobs[job] = callback
        return job

    def after_cancel(self, job):
        self.jobs.pop(job, None)

    def destroy(self):
        self.destroyed = True
        self.jobs.clear()

    def mainloop(self):
        self.events.append('mainloop')
        if self.fake.close == 'stop':
            self.fake.stop_pending = True
            if self.jobs:
                next(iter(self.jobs.values()))()
        elif self.fake.close == 'WM_DELETE_WINDOW':
            self.bindings['WM_DELETE_WINDOW']()
        elif self.fake.close in self.bindings:
            self.bindings[self.fake.close](None)

    wait_window = mainloop


class Tk:
    def __init__(self, close):
        self.close, self.roots, self.widgets = close, [], []
        self.stop_pending = False

    def Tk(self):
        return Root(self)

    def Toplevel(self, parent):
        return Root(self, parent)

    def Label(self, root, **options):
        widget = Widget(root, **options)
        self.widgets.append(widget)
        return widget

    Button = Label


@pytest.fixture
def owner(monkeypatch, tmp_path, request):
    fake = Tk(request.param)
    monkeypatch.setattr(ca, 'tk', fake)
    monkeypatch.setattr(screen, '_HiddenTk', lambda: Root(fake, hidden=True))
    monkeypatch.setattr(ca, '_STARTUP_NOTICE_DIRECT_SYNC_ROOT', tmp_path / 'relay')
    monkeypatch.setattr(ca, '_startup_check_observe', lambda *_args, **_kwargs: False)
    monkeypatch.setattr(ca, '_consume_startup_app_stop_request',
                        lambda _root: fake.stop_pending)
    monkeypatch.setattr(ca, '_show_startup_notice_native',
                        lambda *_args: pytest.fail('native fallback on healthy fake Tk'))
    monkeypatch.setattr(ca, 'build_container_audit_storage_paths',
                        lambda **_kwargs: SimpleNamespace(data_root=tmp_path / 'data',
                                                         direct_sync_root=tmp_path / 'relay'))
    monkeypatch.setattr(ca, 'acquire_runtime_instance',
                        lambda _root: (_ for _ in ()).throw(OSError('synthetic lock failure')))
    failures = []
    bridge = SimpleNamespace(fail_owner=failures.append)

    def run(action):
        def gui(_arguments):
            assert ca.tk.Tk is screen._HiddenTk
            action()
            return 3
        monkeypatch.setattr(ca, '_run_gui_application', gui)
        original_host = dict(ca.CA_SCREEN_HOST)
        original_tk = fake.Tk
        result = screen.owner_main_for(ca, [])(bridge)
        if result is None and ca.CA_SCREEN_HOST.get('error') is not None:
            raise ca.CA_SCREEN_HOST['error']
        assert result == 3
        assert {key: value for key, value in ca.CA_SCREEN_HOST.items() if key != 'exit'} == {
            key: value for key, value in original_host.items() if key != 'exit'}
        assert fake.Tk == original_tk
        assert len(failures) == 1 and isinstance(failures[0], screen.CaStartupRefused)

    return fake, run


@pytest.mark.parametrize('owner', ['<Return>', '<KP_Enter>', 'WM_DELETE_WINDOW', 'stop'], indirect=True)
@pytest.mark.parametrize('condition', ['lock', 'onboarding', 'missing', 'read', 'encoding'])
def test_web_owned_startup_errors_have_visible_owner_and_close_both(
    owner, monkeypatch, tmp_path, condition,
):
    fake, run = owner
    app_root = SimpleNamespace(destroy=lambda: None)
    if condition == 'lock':
        action = lambda: ca._prepare_gui_startup(data_root=tmp_path / 'data')
    elif condition == 'onboarding':
        action = lambda: ca._show_first_run_onboarding_error(ca.CurrentUserOnboardingError(
            'SETUP_FAILED', report_path=tmp_path / 'report.json', status='RECOVERY_REQUIRED'))
    else:
        def fail_open(*_args, **_kwargs):
            error = {'missing': FileNotFoundError('missing'), 'read': OSError('unreadable'),
                     'encoding': UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid')}[condition]
            raise error
        monkeypatch.setattr(ca, 'get_verified_catalog_snapshot', lambda _path: None)
        monkeypatch.setattr(ca, 'requires_verified_catalog_snapshot', lambda _path: False)
        monkeypatch.setattr(ca, 'open', fail_open, raising=False)
        action = lambda: ca.ContainerAudit.load_items(SimpleNamespace(root=app_root))
    run(action)
    assert len(fake.roots) == 2
    visible, dialog = fake.roots
    assert visible.caption == '이적 시작 안내'
    for root in (visible, dialog):
        assert not root.hidden and root.destroyed
        assert 'deiconify' in root.events and 'lift' in root.events and 'focus' in root.events
        assert ('-topmost', True) in root.events and ('-topmost', False) in root.events
        assert not root.jobs
    assert dialog.parent is visible and 'transient' in dialog.events
    assert 'button-focus' in dialog.events


@pytest.mark.parametrize('web', [False, True])
def test_absent_integrity_is_nonblocking_banner_and_scan_still_works(
    startup, monkeypatch, tmp_path, web,
):
    app, _released = startup
    windows = []
    monkeypatch.setattr(ca, '_show_startup_notice', lambda *_args, **_kwargs: windows.append(True))
    monkeypatch.setattr(ca, 'consume_pending_machine_onboarding', lambda *_args: None)
    monkeypatch.setattr(ca, '_first_run_onboarding_enabled', lambda: True)
    monkeypatch.setattr(ca, 'onboard_current_user',
                        lambda *_args, **_kwargs: {'bootstrap_integrity': 'absent'})
    monkeypatch.setattr(ca, 'resolve_current_user_onboarding_paths',
                        lambda *_args: SimpleNamespace(onboarding_report_path=tmp_path / 'report.json'))
    import data_generation_guard
    monkeypatch.setattr(data_generation_guard, '_runtime_release', lambda: {
        'version': ca.CURRENT_VERSION, 'build_id': 'a' * 40,
        'data_compatible_min_version': ca.CURRENT_VERSION, 'compatibility_verified': False,
    })
    _offline_catalog(monkeypatch, tmp_path)
    monkeypatch.setitem(ca.CA_SCREEN_HOST, 'active', web)
    prepared = ca._prepare_gui_startup()
    assert isinstance(prepared, tuple) and prepared[0] is app
    assert windows == []
    if web:
        alerts = screen._alerts(app, app._warning_state_presenter().state, [], ca.datetime.datetime.now())
        assert {'kind': 'warn', 'text': WARNING} in alerts
    else:
        assert WARNING in app.catalog_notice_label.options['text']
    public_scan(app, COMPACT_QR + '|QT=2')
    public_scan(app, ITEM + '-SERIAL-001')
    assert app.current_tray.scanned_barcodes == [ITEM + '-SERIAL-001']
    prepared[1].release()

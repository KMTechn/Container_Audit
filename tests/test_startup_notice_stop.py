"""Independent startup notices use bounded fake Tk, never a real window."""
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import runtime_instance_win32 as native
import storage_policy
import user_relay
from tests.test_startup_catalog_notice import startup, flow, fixed_operation_lease_clock


MODES = ('unavailable', 'onboarding', 'integrity', 'catalog',
         'generation', 'data-root', 'legacy-update', 'instance-lock')
STOP_TRACE = {'stage': 'APP_STOP_REQUESTED_CLOSE', 'message': '멈춤 요청으로 닫힘'}


class FakeTk:
    def __init__(self, publish=None, manual=False):
        self.roots = []
        self.labels = []
        self.buttons = []
        self.publish = publish
        self.manual = manual

    def Tk(self):
        root = FakeRoot(self)
        self.roots.append(root)
        return root

    def Label(self, root, **kwargs):
        self.labels.append(kwargs['text'].encode('utf-8'))
        return SimpleNamespace(pack=lambda **_kwargs: None)

    def Button(self, root, **kwargs):
        self.buttons.append(kwargs)
        return SimpleNamespace(pack=lambda **_kwargs: None)


class FakeRoot:
    def __init__(self, owner):
        self.owner = owner
        self.jobs = {}
        self.next_job = 0
        self.now = 0
        self.destroyed = False
        self.protocols = {}

    def title(self, value):
        self.caption = value

    def resizable(self, *_args):
        pass

    def withdraw(self):
        pass

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def after(self, delay, callback):
        self.next_job += 1
        self.jobs[self.next_job] = (self.now + delay, callback)
        return self.next_job

    def after_cancel(self, job):
        self.jobs.pop(job, None)

    def destroy(self):
        self.destroyed = True
        self.jobs.clear()

    def mainloop(self):
        if self.owner.publish:
            self.owner.publish()
        if self.owner.manual:
            self.protocols['WM_DELETE_WINDOW']()
            return
        # Both callback count and virtual time are bounded, including on RED.
        for _ in range(8):
            if self.destroyed or not self.jobs:
                return
            job = min(self.jobs, key=lambda key: self.jobs[key][0])
            when, callback = self.jobs.pop(job)
            assert when <= 4000
            self.now = when
            callback()


@pytest.fixture
def notice(monkeypatch, tmp_path):
    root = tmp_path / 'relay'
    traces, native_calls = [], []
    monkeypatch.setattr(ca, '_STARTUP_NOTICE_DIRECT_SYNC_ROOT', root, raising=False)
    monkeypatch.setattr(ca, 'build_container_audit_storage_paths',
                        lambda **_kwargs: SimpleNamespace(direct_sync_root=root, data_root=tmp_path / 'data'))
    monkeypatch.setattr(ca, '_startup_check_observe', lambda *_args, **_kwargs: False)
    monkeypatch.setattr(ca, '_record_startup_notice_stop',
                        lambda **fields: traces.append(fields), raising=False)
    monkeypatch.setattr(user_relay, 'native_app_process_snapshot', lambda: [])
    monkeypatch.setattr(user_relay, 'request_user_relay_stop',
                        lambda *_args, **_kwargs: {'status': 'STOPPED'})
    for name in ('showerror', 'showwarning', 'showinfo'):
        monkeypatch.setattr(ca.messagebox, name,
                            lambda *args, **kwargs: native_calls.append((args, kwargs)))
    monkeypatch.setattr(native, 'timed_notice',
                        lambda *args, **kwargs: native_calls.append((args, kwargs)))
    fake = FakeTk(publish=lambda: user_relay.request_app_stop(root, timeout_seconds=0))
    monkeypatch.setattr(ca, 'tk', fake)
    return SimpleNamespace(root=root, traces=traces, native=native_calls, tk=fake)


def invoke(mode, monkeypatch, tmp_path):
    if mode == 'unavailable':
        return ca._show_startup_unavailable('시작 확인 안내')
    if mode == 'onboarding':
        return ca._show_first_run_onboarding_error(ca.CurrentUserOnboardingError(
            'SETUP_FAILED', report_path=tmp_path / 'report.json', status='RECOVERY_REQUIRED'))
    if mode == 'integrity':
        return ca._show_bootstrap_integrity_warning(tmp_path / 'report.json')
    if mode == 'catalog':
        return ca._show_item_catalog_startup_error('HTTP_ERROR', http_status_code=503)
    if mode in ('generation', 'data-root'):
        relay_root = ca._STARTUP_NOTICE_DIRECT_SYNC_ROOT
        error = (ca.DataGenerationBlocked({'status': 'REFUSE'}) if mode == 'generation'
                 else ca.DataRootUnavailableError('unavailable'))

        def refuse(**_kwargs):
            ca._STARTUP_NOTICE_DIRECT_SYNC_ROOT = relay_root
            raise error

        monkeypatch.setattr(ca, '_prepare_gui_startup', refuse)
        return ca._run_gui_application([])
    if mode == 'instance-lock':
        def no_lock(_root):
            raise OSError('instance lock unavailable')

        monkeypatch.setattr(ca, 'acquire_runtime_instance', no_lock)
        return ca._prepare_gui_startup(data_root=tmp_path / 'data')
    return ca._prompt_and_apply_update({'version': 'test-version'})


@pytest.mark.parametrize('mode', MODES)
def test_each_independent_notice_consumes_stop_and_returns_safely(
        notice, monkeypatch, tmp_path, mode):
    result = invoke(mode, monkeypatch, tmp_path)
    assert len(notice.tk.roots) == 1
    assert notice.tk.roots[0].destroyed
    assert notice.tk.roots[0].now == 500
    assert notice.traces == [STOP_TRACE]
    assert user_relay.read_app_stop_request(notice.root) is None
    assert not notice.native
    assert result == (1 if mode in ('generation', 'data-root') else
                      True if mode == 'integrity' else None)


@pytest.mark.parametrize('mode', MODES)
def test_manual_close_keeps_message_bytes_and_does_not_report_stop(
        notice, monkeypatch, tmp_path, mode):
    notice.tk.publish = None
    notice.tk.manual = True
    invoke(mode, monkeypatch, tmp_path)
    expected = {
        'unavailable': '시작 확인 안내',
        'onboarding': ca.MACHINE_ONBOARDING_ERROR_MESSAGES['RECOVERY_REQUIRED'],
        'integrity': f'{ca.BOOTSTRAP_INTEGRITY_WARNING_MESSAGE}\n보고서: {tmp_path / "report.json"}',
        'catalog': f'{ca.ITEM_CATALOG_STARTUP_ERROR_MESSAGE}\n회사 서버 오류(코드 503).\n오류 코드: HTTP_ERROR',
        'generation': ca.DataGenerationBlocked({'status': 'REFUSE'}).user_message,
        'data-root': storage_policy.DATA_ROOT_ERROR_MESSAGE,
        'legacy-update': f'새로운 버전(test-version)이 확인되었습니다. (현재: {ca.CURRENT_VERSION})\n\n'
                         + ca.RUNTIME_UPDATE_BOOTSTRAP_MESSAGE,
        'instance-lock': '데이터 충돌 방지를 위한 실행 잠금을 확인하지 못했습니다. '
                         '프로그램을 시작하지 않고 관리자에게 문의합니다.',
    }
    assert notice.tk.labels == [expected[mode].encode('utf-8')]
    titles = {
        'unavailable': '프로그램 시작 확인',
        'onboarding': ca.FIRST_RUN_ONBOARDING_ERROR_TITLE,
        'integrity': ca.BOOTSTRAP_INTEGRITY_WARNING_TITLE,
        'catalog': ca.ITEM_CATALOG_STARTUP_ERROR_TITLE,
        'generation': '자료 판 확인',
        'data-root': '이적 검사 데이터 폴더 오류',
        'legacy-update': '관리자 업데이트 필요',
        'instance-lock': '프로그램 실행 잠금 실패',
    }
    assert notice.tk.roots[0].caption.encode('utf-8') == titles[mode].encode('utf-8')
    assert notice.tk.buttons[0]['text'] == '닫기'
    assert not notice.traces
    assert not notice.native


@pytest.mark.parametrize('mode', MODES)
def test_tk_creation_failure_uses_thirty_second_native_bound(
        notice, monkeypatch, tmp_path, mode):
    calls = []

    def no_tk():
        raise RuntimeError('Tk unavailable')

    monkeypatch.setattr(notice.tk, 'Tk', no_tk)
    monkeypatch.setattr(ca, '_show_startup_notice_native',
                        lambda *args, **kwargs: calls.append((args, kwargs)), raising=False)
    result = invoke(mode, monkeypatch, tmp_path)
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0] and args[1]
    assert args[2] == ('warning' if mode == 'integrity' else
                       'info' if mode in ('legacy-update', 'unavailable') else 'error')
    assert not notice.native
    assert not notice.traces
    assert result == (1 if mode in ('generation', 'data-root') else None)


def show_common(notice, record_stop=None):
    return ca._show_stop_aware_startup_notice(
        '프로그램 시작 확인', '시작 확인 안내', 'error', direct_sync_root=notice.root,
        record_stop=record_stop or (lambda **fields: notice.traces.append(fields)))


def test_common_watcher_closes_even_when_trace_write_fails(notice):
    def denied(**_fields):
        raise OSError('diagnostic unavailable')

    assert show_common(notice, denied) is True
    assert notice.tk.roots[0].destroyed
    assert user_relay.read_app_stop_request(notice.root) is None
    assert not notice.native


def test_common_watcher_retries_a_transient_request_read_error(notice, monkeypatch):
    consume = ca._consume_startup_app_stop_request
    calls = []

    def once(root):
        calls.append(root)
        if len(calls) == 1:
            raise OSError('request temporarily unavailable')
        return consume(root)

    monkeypatch.setattr(ca, '_consume_startup_app_stop_request', once)
    assert show_common(notice) is True
    assert notice.tk.roots[0].now == 1000
    assert notice.traces == [STOP_TRACE]


def test_common_watcher_preserves_stop_acceptance_when_consume_is_fenced(notice, monkeypatch):
    def denied(*_args):
        raise OSError('request cleanup denied')

    monkeypatch.setattr(user_relay, 'consume_app_stop_request', denied)
    assert show_common(notice) is True
    assert notice.traces == [STOP_TRACE]
    assert user_relay.read_app_stop_request(notice.root) is not None


@pytest.mark.parametrize('request_kind', ('old', 'malformed'))
def test_common_watcher_keeps_existing_request_validation(notice, request_kind):
    def publish():
        user_relay.request_app_stop(notice.root, timeout_seconds=0)
        path = user_relay.app_stop_path(notice.root)
        payload = json.loads(path.read_text(encoding='utf-8'))
        if request_kind == 'old':
            payload['requested_at'] = (ca._APP_PROCESS_STARTED_AT - timedelta(seconds=1)).isoformat()
        else:
            payload['request_id'] = 'invalid'
        path.write_text(json.dumps(payload), encoding='utf-8')

    notice.tk.publish = publish
    assert show_common(notice) is False
    assert not notice.traces
    assert notice.tk.roots[0].now == 4000
    assert user_relay.app_stop_path(notice.root).exists() == (request_kind == 'malformed')


def test_common_manual_close_cancels_the_scheduled_poll(notice):
    notice.tk.publish = None
    notice.tk.manual = True
    assert show_common(notice) is False
    assert not notice.tk.roots[0].jobs
    assert not notice.traces


def test_stop_racing_with_manual_close_is_not_treated_as_continue(notice):
    notice.tk.manual = True
    assert show_common(notice) is True
    assert notice.traces == [STOP_TRACE]
    assert user_relay.read_app_stop_request(notice.root) is None


def test_stop_arriving_during_native_fallback_is_not_treated_as_continue(notice, monkeypatch):
    def no_tk():
        raise RuntimeError('Tk unavailable')

    monkeypatch.setattr(notice.tk, 'Tk', no_tk)
    monkeypatch.setattr(ca, '_show_startup_notice_native',
                        lambda *_args: user_relay.request_app_stop(notice.root, timeout_seconds=0))
    assert show_common(notice) is True
    assert notice.traces == [STOP_TRACE]
    assert user_relay.read_app_stop_request(notice.root) is None


@pytest.mark.parametrize('kind,flag', [('error', 0x10), ('warning', 0x30), ('info', 0x40)])
def test_common_tk_failure_preserves_native_kind_and_thirty_second_bound(
        notice, monkeypatch, kind, flag):
    calls = []

    def no_tk():
        raise RuntimeError('Tk unavailable')

    monkeypatch.setattr(notice.tk, 'Tk', no_tk)
    monkeypatch.setattr(ca, '_show_startup_notice_native',
                        lambda *args: calls.append(args), raising=False)
    assert ca._show_stop_aware_startup_notice(
        '고정 제목', '고정 안내', kind, direct_sync_root=notice.root,
        record_stop=lambda **_fields: None) is False
    assert calls == [('고정 제목', '고정 안내', kind)]


@pytest.mark.parametrize('kind,flag', [('error', 0x10), ('warning', 0x30), ('info', 0x40)])
def test_native_fallback_passes_the_thirty_second_timeout(monkeypatch, kind, flag):
    import ctypes

    class Notice:
        def __call__(self, *args):
            self.args = args
            return 1

    notice = Notice()
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *_args, **_kwargs:
                        SimpleNamespace(MessageBoxTimeoutW=notice))
    ca._show_startup_notice_native('고정 제목', '고정 안내', kind)
    assert notice.args == (None, '고정 안내', '고정 제목', flag, 0, 30000)


@pytest.mark.parametrize('mode', MODES)
def test_native_fallback_failure_keeps_safe_return(notice, monkeypatch, tmp_path, mode):
    def unavailable(*_args, **_kwargs):
        raise OSError('notice unavailable')

    monkeypatch.setattr(notice.tk, 'Tk', unavailable)
    monkeypatch.setattr(ca, '_show_startup_notice_native', unavailable, raising=False)
    assert invoke(mode, monkeypatch, tmp_path) == (1 if mode in ('generation', 'data-root') else None)
    assert not notice.native


def test_unknown_relay_root_uses_bounded_native_without_guessing_or_consuming(
        notice, monkeypatch, tmp_path):
    calls = []
    user_relay.request_app_stop(notice.root, timeout_seconds=0)
    request = user_relay.app_stop_path(notice.root).read_bytes()

    def invalid_paths(**_kwargs):
        raise ca.DataRootUnavailableError('selected root unavailable')

    monkeypatch.setattr(ca, 'build_container_audit_storage_paths', invalid_paths)
    monkeypatch.setattr(ca, '_show_startup_notice_native',
                        lambda *args: calls.append(args), raising=False)
    assert ca._run_gui_application(['--data-root', str(tmp_path / 'unavailable')]) == 1
    assert not notice.tk.roots
    assert user_relay.app_stop_path(notice.root).read_bytes() == request
    assert calls == [('이적 검사 데이터 폴더 오류', storage_policy.DATA_ROOT_ERROR_MESSAGE, 'error')]
    assert not notice.traces
    assert not notice.native


def test_stop_trace_uses_only_the_fixed_stdout_line(capsys):
    ca._record_startup_notice_stop(**STOP_TRACE)
    assert capsys.readouterr().out == 'stage="APP_STOP_REQUESTED_CLOSE" message="멈춤 요청으로 닫힘"\n'


def test_stop_trace_output_failure_still_returns_safely(monkeypatch):
    def denied(*_args, **_kwargs):
        raise OSError('stdout unavailable')

    monkeypatch.setattr('builtins.print', denied)
    ca._record_startup_notice_stop(**STOP_TRACE)


def test_owned_update_notice_preserves_parent_and_acknowledgement(monkeypatch):
    calls = []
    parent = object()
    monkeypatch.setattr(ca.messagebox, 'showinfo', lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(ca, '_show_startup_notice',
                        lambda *_args, **_kwargs: pytest.fail('owned notice became independent'))
    assert ca._prompt_and_apply_update({'version': 'test-version'}, parent=parent) is None
    assert calls == [(('관리자 업데이트 필요',
                       f'새로운 버전(test-version)이 확인되었습니다. (현재: {ca.CURRENT_VERSION})\n\n'
                       + ca.RUNTIME_UPDATE_BOOTSTRAP_MESSAGE), {'parent': parent})]


def test_integrity_stop_never_enters_the_next_startup_unit(startup, monkeypatch, tmp_path):
    _app, released = startup
    monkeypatch.setattr(ca, 'consume_pending_machine_onboarding', lambda *_args: None)
    monkeypatch.setattr(ca, '_first_run_onboarding_enabled', lambda: True)
    monkeypatch.setattr(ca, 'onboard_current_user', lambda *_args, **_kwargs: {'bootstrap_integrity': 'absent'})
    monkeypatch.setattr(ca, 'resolve_current_user_onboarding_paths',
                        lambda *_args: SimpleNamespace(onboarding_report_path=tmp_path / 'report.json'))
    monkeypatch.setattr(ca, '_show_bootstrap_integrity_warning', lambda *_args: True)
    monkeypatch.setattr(ca, 'record_before_owner_paths',
                        lambda *_args, **_kwargs: pytest.fail('next startup unit entered after stop'))
    monkeypatch.setattr(ca, 'prepare_startup_item_catalog',
                        lambda: pytest.fail('catalog started after stop'))
    assert ca._prepare_gui_startup() == 0
    assert len(released) == 1


def _common_notice_child(root, ready):
    """A guarded Python child with fake Tk and an actual official request file."""
    class WaitingRoot(FakeRoot):
        def mainloop(self):
            Path(ready).write_text('ready', encoding='ascii')
            for _ in range(20):
                if self.destroyed or not self.jobs:
                    return
                time.sleep(0.1)
                job = min(self.jobs, key=lambda key: self.jobs[key][0])
                when, callback = self.jobs.pop(job)
                self.now = when
                callback()

    fake = FakeTk()
    fake.Tk = lambda: WaitingRoot(fake)
    ca.tk = fake
    traces = []
    stopped = ca._show_stop_aware_startup_notice(
        '프로그램 시작 확인', '시작 확인 안내', 'error', direct_sync_root=Path(root),
        record_stop=lambda **fields: traces.append(fields))
    assert stopped and traces == [STOP_TRACE]
    raise SystemExit(0)


def test_official_request_stops_an_isolated_fake_tk_child(notice, tmp_path):
    ready = tmp_path / 'child-ready'
    code = ('from tests.test_startup_notice_stop import _common_notice_child; '
            'import sys; _common_notice_child(sys.argv[1], sys.argv[2])')
    child = subprocess.Popen(
        [sys.executable, '-B', '-c', code, str(notice.root), str(ready)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        assert ready.exists(), 'isolated child did not reach its fake Tk loop'
        user_relay.request_app_stop(notice.root, timeout_seconds=0)
        child.communicate(timeout=10)
        assert child.returncode == 0
        assert child.poll() == 0
        assert user_relay.read_app_stop_request(notice.root) is None
    finally:
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=5)

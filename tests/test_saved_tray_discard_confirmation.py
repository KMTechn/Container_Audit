"""G74: exercise the real recovery/delete path with a bounded, windowless Tk pump."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen


class Widget:
    def __init__(self, pump, parent=None, **options):
        self.pump, self.parent, self.options = pump, parent, options
        self.bindings = {}
        self.destroyed = False
        pump.widgets.append(self)

    def pack(self, **_options):
        pass

    def title(self, value):
        self.caption = value

    def transient(self, _parent):
        pass

    def resizable(self, *_args):
        pass

    def protocol(self, name, callback):
        self.bindings[name] = callback

    def bind(self, name, callback, *_args):
        self.bindings[name] = callback

    def focus_set(self):
        self.pump.focus = self

    def grab_set(self):
        pass

    def wait_window(self):
        self.pump.dispatch(self)

    def destroy(self):
        self.destroyed = True


class Pump:
    def __init__(self, events):
        self.events, self.widgets, self.focus = events, [], None
        self.initial_focus = None
        self.keyboard_yes = 0

    def widget(self, parent=None, **options):
        return Widget(self, parent, **options)

    def top(self, parent=None, **options):
        if self.events == ['cannot_show']:
            raise ca.tk.TclError('headless creation failure')
        self.window = self.widget(parent, **options)
        return self.window

    @property
    def yes(self):
        return next(w for w in self.widgets if w.options.get('text') == '예, 영구 삭제')

    @property
    def no(self):
        return next(w for w in self.widgets if w.options.get('text') == '아니오(지우지 않음)')

    def dispatch(self, window):
        self.initial_focus = self.focus
        assert len(self.events) <= 64, 'fake pump must remain bounded'
        for event in self.events:
            if window.destroyed:
                break
            if event == 'mouse_yes':
                # Only the explicitly bound mouse handler can authorize deletion.
                self.yes.bindings['<ButtonRelease-1>'](SimpleNamespace(widget=self.yes, x=1, y=1))
            elif event == 'close':
                window.bindings['WM_DELETE_WINDOW']()
            else:
                target = self.yes if event in ('<space>', '<Key-space>') else self.focus
                callback = target.bindings.get(event) or window.bindings.get(event)
                result = callback(SimpleNamespace(widget=target)) if callback else None
                # Tk Button class keyboard activation only survives an unconsumed event.
                if target is self.yes and result != 'break' and event in ('<Return>', '<space>', '<Key-space>'):
                    command = target.options.get('command')
                    if command:
                        self.keyboard_yes += 1
                        command()
        assert window.destroyed, 'dialog did not terminate during the bounded event script'


@pytest.fixture
def recovery(monkeypatch, tmp_path):
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    app.root = SimpleNamespace(after=lambda *_a: None, after_cancel=lambda *_a: None)
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = 'saved-work.json'
    (tmp_path / app.CURRENT_TRAY_STATE_FILE).write_text('{}', encoding='utf-8')
    app.worker_name = 'current-worker'
    app.current_tray = ca.TraySession()
    state = {'worker_name': 'previous-worker', 'master_label_code': 'headless-tray', 'operation_id': 'headless-operation'}
    monkeypatch.setattr(ca, 'read_recovery_file', lambda *_a, **_k: SimpleNamespace(value=state, raw=b'{}', verified=True))
    for name in ('_resume_storage_failure_slots', 'show_worker_input_screen', 'show_status_message', '_show_field_notice'):
        monkeypatch.setattr(app, name, lambda *_a, **_k: None)
    for name in ('_reject_residual_tag', '_paired_preflight_blocks_label', '_is_completed_tray_state', '_owns_worker_record'):
        monkeypatch.setattr(app, name, lambda *_a, **_k: False)
    for name in ('_reconcile_activation_event_from_state', '_reconcile_parked_restore_from_state'):
        monkeypatch.setattr(app, name, lambda *_a, **_k: True)
    for name in ('_operator_review_snapshot_from_state', '_completion_event_contract_from_state'):
        monkeypatch.setattr(app, name, lambda *_a, **_k: None)
    calls = []
    app._log_saved_tray_discarded = lambda *a, **k: calls.append(('audit', a, k)) or True
    app._delete_current_tray_state = lambda: calls.append(('delete',)) or True
    app._request_operation_lease_release = lambda *a: calls.append(('release', a))
    # Baseline Windows default-yes behavior: scanner suffix/accelerator accepts it.
    monkeypatch.setattr(ca.messagebox, 'askyesno', lambda *_a, **_k: True)
    return app, calls, state


def install_pump(monkeypatch, events):
    pump = Pump(events)
    monkeypatch.setattr(ca.tk, 'Toplevel', pump.top)
    for name in ('Label', 'Frame', 'Button'):
        monkeypatch.setattr(ca.tk, name, pump.widget)
    return pump


def run_recovery(recovery):
    app, calls, _state = recovery
    app._load_current_tray_state(_recovery_choice=False)
    return [call[0] for call in calls]


def test_return_and_scanner_suffix_do_not_delete(recovery, monkeypatch):
    for key in ('<Return>', '<KP_Enter>'):
        install_pump(monkeypatch, [key])
        assert run_recovery(recovery) == []


def test_barcode_characters_including_y_do_not_delete(recovery, monkeypatch):
    install_pump(monkeypatch, list('SCAN-Yy-한글-123') + ['<Return>'])
    assert run_recovery(recovery) == []


def test_mouse_yes_keeps_downstream_deletion_sequence(recovery, monkeypatch):
    install_pump(monkeypatch, ['mouse_yes'])
    assert run_recovery(recovery) == ['audit', 'delete', 'release']
    assert recovery[1][0][1] == (recovery[2],)
    assert recovery[1][0][2]['discarded_worker_name'] == 'previous-worker'
    assert recovery[1][2][1] == ('headless-operation',)
    assert recovery[0].current_tray.master_label_code is None


def test_yes_has_no_keyboard_activation_and_initial_focus_is_no(recovery, monkeypatch):
    pump = install_pump(monkeypatch, ['<space>', '<Key-space>', '<Return>'])
    assert run_recovery(recovery) == []
    assert pump.initial_focus is pump.no
    assert pump.yes.options['takefocus'] == 0
    assert pump.yes.options.get('underline', -1) == -1
    assert not pump.yes.options.get('command')
    assert pump.no.options['default'] == ca.tk.ACTIVE
    assert pump.keyboard_yes == 0
    source = Path(ca.__file__).read_text(encoding='utf-8-sig')
    tree = ast.parse(source)
    load = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_load_current_tray_state')
    assert not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr == 'askyesno' for n in ast.walk(load))


def test_escape_and_window_close_do_not_delete(recovery, monkeypatch):
    for event in ('<Escape>', 'close'):
        install_pump(monkeypatch, [event])
        assert run_recovery(recovery) == []


def test_cannot_show_dialog_does_not_delete(recovery, monkeypatch):
    install_pump(monkeypatch, ['cannot_show'])
    assert run_recovery(recovery) == []


def test_web_question_scan_cannot_answer_or_delete(recovery, monkeypatch):
    app, calls, _state = recovery
    original = getattr(app, '_confirm_saved_tray_discard', None)
    processor = screen.CaProcessor(app)
    answers = []
    monkeypatch.setattr(processor, '_new_answer', lambda: SimpleNamespace(get=lambda: 'no', set=answers.append))
    monkeypatch.setattr(processor, '_push', lambda: None)
    def wait(_answer):
        sheet = processor.sheet
        assert sheet['actions'][0]['go'] == 'command:choose:ask_no'
        assert sheet['actions'][0]['quiet'] is True
        for text in ('SCAN-Yy-123', ''):
            result = processor.scan(text, {})
            assert result['accepted'] is False
        assert answers == []
        assert calls == []
    monkeypatch.setattr(processor, '_wait', wait)
    monkeypatch.setattr(ca.tk, 'Toplevel', lambda *_a, **_k: pytest.fail('web path created Tk dialog'))
    processor.install()
    try:
        assert run_recovery(recovery) == []
        assert processor._answer is None
    finally:
        processor.shutdown()
    if original is not None:
        assert app._confirm_saved_tray_discard == original

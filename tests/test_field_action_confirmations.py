"""F6: scanner text never confirms an operator's pending action (DESIGN §1)."""
from types import SimpleNamespace as NS

import pytest
import Container_Audit as ca
from tests.test_container_p0_contracts import _preflight_hold_ownership_app
from tests.test_observed_scanner_completion import ScannerEntry
from tests.test_phs_reconciliation_workflow import _ImmediateRoot, _Value
from tests.test_container_audit_contracts import _headless_app

QR = 'PHS=2|SRC=KMTECH_INPUT_TAG|ITG=tag-1|CLC=AAA2270730100|LBL=label-1|HSH=0123456789abcdef|QT=4'
LEGACY = 'CLC=AAA2270730100|SPC=XXX|PHS=1'
LEGACY_Y = 'CLC=AAA2270730100|SPC=YYY|PHS=1'
SCANS = ['', QR, 'KMCMD:EXCHANGE', 'KMCMD:UNDO', LEGACY, LEGACY_Y, 'Y', 'N']


def scanner_model(monkeypatch, raw):
    """Reuse sub-356's documented Korean Y/N/default model without native UI."""
    calls = []
    def ask(_title, _message, **options):
        calls.append('askyesno')
        for char in raw.upper():
            if char in 'YN':
                return char == 'Y'
        return options.get('default', 'yes') == 'yes'
    monkeypatch.setattr(ca.messagebox, 'askyesno', ask)
    return calls


def scanner_surface(app):
    delivered = []
    app.root = _ImmediateRoot()
    app.scan_entry = ScannerEntry('')
    app._start_warning_beep = lambda: None
    app._stop_warning_beep = lambda: None
    app._render_warning_state = lambda: None
    app.show_fullscreen_warning = lambda *_a: None
    app.show_status_message = lambda *_a, **_k: None
    app._schedule_focus_return = lambda: None
    app._operator_review_blocks_mutation = lambda: False
    app._scan_entry_admission_block_reason = lambda: ''
    app._set_scan_callback_pending = lambda value: setattr(app, '_scan_callback_pending', value)
    app._process_barcode_logic = delivered.append
    return delivered


def scan(app, raw):
    app.scan_entry.insert(0, raw)
    app.process_barcode()


def choose(app, text):
    """Explicit mouse-button command when this fixture has no Tk notice frame."""
    callback = next(callback for label, callback in app._inline_scan_choices if label == text)
    app._inline_scan_choices = []
    app._inline_choice_on_scan = None
    return callback()


def worker_app():
    app = _headless_app()
    app.worker_name = 'worker-1'
    app.current_tray = ca.TraySession(master_label_code='ACTIVE', scanned_barcodes=['PRODUCT-A'])
    app._save_current_tray_state = lambda: True
    app._log_event = lambda *_a, **_k: True
    app._disable_remembered_worker_start = lambda: True
    app._preflight_context_blocks_mutation = lambda: False
    app._operator_review_blocks_mutation = lambda: False
    app._phs_label_exchange_blocks_tray_transition = lambda *_a: False
    app._transfer_member_exchange_blocks_local_action = lambda *_a: False
    app.master_label_replace_state = None
    app._end_work_session = lambda **_k: True
    app._cancel_all_jobs = lambda: None
    app._invalidate_pending_scan_callbacks = lambda: None
    app.show_worker_input_screen = lambda: None
    return app


def restore_app(tmp_path, monkeypatch):
    _module, app, store = _preflight_hold_ownership_app(tmp_path, monkeypatch)
    store.start(worker=app.worker_name, master_raw=QR, scan_epoch=1)
    store.append('PRODUCT-A')
    store.mark_failed(error_code='PHS2_PREFLIGHT_UNAVAILABLE')
    path = store.quarantine(app._preflight_hold_quarantine_directory(), reason='test').path
    app._preflight_hold_snapshot = None
    return app, store, path


def reprint_app():
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    app.current_tray = ca.TraySession()
    app.phs_label_reprint_confirm_var = _Value(False)
    app._phs_reconciliation_context = None
    app._reject_mutation_during_preflight_hold = lambda: False
    app._capture_phs_reconciliation_progress = lambda: {}
    app._update_action_button_states = lambda: None
    effects = []
    app.phs_label_exchange_coordinator = NS(
        journal=NS(load=lambda: {'workflow_kind': 'RECONCILIATION', 'status': 'LOCAL_PRINT_STARTING'}),
        reconciliation=NS(available=True))
    app._ui_task_lane = lambda: NS(submit=lambda task: effects.append(task) or NS(accepted=False))
    return app, effects


@pytest.mark.parametrize('raw', SCANS)
@pytest.mark.parametrize('action', ['worker', 'restore', 'reprint'])
def test_scanner_does_not_approve_pending_action(tmp_path, monkeypatch, raw, action):
    if action == 'worker':
        app = worker_app()
        request = app.change_worker
        unchanged = lambda: app.worker_name == 'worker-1' and app.current_tray.master_label_code == 'ACTIVE'
    elif action == 'restore':
        app, store, path = restore_app(tmp_path, monkeypatch)
        original = path.read_bytes()
        request = lambda: app.restore_quarantined_preflight_hold(str(path))
        unchanged = lambda: path.exists() and path.read_bytes() == original and not store.exists()
    else:
        app, effects = reprint_app()
        request = lambda: app._execute_phs_reconciliation_exchange(recovery_only=True)
        unchanged = lambda: not effects and not app.phs_label_reprint_confirm_var.get()
    delivered = scanner_surface(app)
    dialogs = scanner_model(monkeypatch, raw)
    request()
    assert unchanged(), 'pending choice performed the action before a mouse click'
    scan(app, raw)
    assert unchanged(), 'scanner characters/Enter approved the action'
    assert delivered == ([raw] if raw else [])
    assert app.scan_entry.get() == ''
    assert dialogs == [], 'native yes/no reintroduced into this field action'


@pytest.mark.parametrize('action', ['worker', 'restore', 'reprint'])
def test_explicit_button_still_performs_action(tmp_path, monkeypatch, action):
    if action == 'worker':
        app = worker_app()
        scanner_surface(app)
        app.change_worker()
        choose(app, '작업자 변경')
        assert app.worker_name == '' and not app.current_tray.master_label_code
    elif action == 'restore':
        app, store, path = restore_app(tmp_path, monkeypatch)
        scanner_surface(app)
        app.restore_quarantined_preflight_hold(str(path))
        choose(app, '보류 묶음 복원')
        assert store.exists() and not path.exists()
        assert [item.raw_barcode for item in store.load().items] == ['PRODUCT-A']
    else:
        app, effects = reprint_app()
        scanner_surface(app)
        app._execute_phs_reconciliation_exchange(recovery_only=True)
        choose(app, '실물 확인 후 재출력')
        assert len(effects) == 1


def test_inline_buttons_keep_scanner_focus(monkeypatch):
    focus, widgets = [], []
    class Widget:
        def __init__(self, *_args, **options):
            self.options = options
            widgets.append(self)
        def grid(self, **_options):
            pass
        def destroy(self):
            pass
    monkeypatch.setattr(ca.tk, 'Frame', Widget)
    monkeypatch.setattr(ca.tk, 'Button', Widget)
    app = worker_app()
    delivered = scanner_surface(app)
    app.notice_frame = object()
    app.scan_entry.focus_set = lambda: focus.append('scanner')
    app.show_fullscreen_warning = lambda *_args: focus.append('notice')
    app.change_worker()
    assert focus == ['notice', 'scanner']
    buttons = [w for w in widgets if 'command' in w.options]
    assert all(w.options['takefocus'] is False for w in buttons)
    scan(app, LEGACY_Y)
    assert delivered == [LEGACY_Y] and app.worker_name == 'worker-1'
    assert not app._inline_scan_choices


def test_worker_button_rechecks_guards():
    app = worker_app()
    scanner_surface(app)
    app.change_worker()
    app._preflight_context_blocks_mutation = lambda: True
    choose(app, '작업자 변경')
    assert app.worker_name == 'worker-1'


def test_restore_button_rechecks_worker_authority(tmp_path, monkeypatch):
    app, store, path = restore_app(tmp_path, monkeypatch)
    scanner_surface(app)
    app.restore_quarantined_preflight_hold(str(path))
    app.worker_name = 'other-worker'
    choose(app, '보류 묶음 복원')
    assert path.exists() and not store.exists()


@pytest.mark.parametrize('changed', ['guard', 'journal', 'read_failed'])
def test_reprint_button_cannot_leave_stale_approval(changed):
    app, effects = reprint_app()
    scanner_surface(app)
    app._execute_phs_reconciliation_exchange(recovery_only=True)
    if changed == 'guard':
        app._reject_mutation_during_preflight_hold = lambda: True
    elif changed == 'journal':
        app.phs_label_exchange_coordinator.journal.load = lambda: {'status': 'OTHER_TARGET'}
    else:
        app.phs_label_exchange_coordinator.journal.load = lambda: (_ for _ in ()).throw(OSError('synthetic read failure'))
    choose(app, '실물 확인 후 재출력')
    assert effects == [] and not app.phs_label_reprint_confirm_var.get()

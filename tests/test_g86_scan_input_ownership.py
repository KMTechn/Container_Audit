"""G86 scanner ownership regressions; source methods run without starting the app."""
"""G86 RED probes: compile unchanged production method AST, no app startup or I/O.

Entry models Tk's disabled delete/insert. Pump is bounded to 200 callbacks and
0.5 virtual seconds. The final success sink records only in memory.
"""
import ast
import copy
import importlib.util
import sys
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ITEM = '1234567890123'
FIRST = ITEM + '-OLD'
SECOND = ITEM + '-NEW'


def module_at(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CA_IDENTITY = module_at('_g86_ca_identity', 'product_identity_port.py')


class TclError(Exception):
    pass


class Entry:
    def __init__(self):
        self.value = ''
        self.state = 'normal'
        self.fail_delete = 0

    def get(self):
        return self.value

    def cget(self, key):
        return self.state

    def configure(self, **kw):
        self.state = kw.get('state', self.state)

    def delete(self, *args):
        if self.fail_delete:
            self.fail_delete -= 1
            raise TclError('injected delete failure')
        if self.state == 'normal':
            self.value = ''

    def insert(self, at, value):
        if self.state == 'normal':
            self.value = (self.value + value) if at == 'end' else (value + self.value)


class Pump:
    def __init__(self):
        self.jobs = []

    def after(self, ms, fn, *args):
        self.jobs.append((ms / 1000, fn, args))

    def drain(self):
        elapsed = 0.0
        for _ in range(200):
            if not self.jobs:
                return
            delay, fn, args = self.jobs.pop(0)
            elapsed += delay
            assert elapsed <= 0.5, 'virtual-time cap'
            fn(*args)
        assert not self.jobs, 'callback-count cap'


def methods(relative, names, extra=None):
    path = ROOT / relative
    tree = ast.parse(path.read_text(encoding='utf-8-sig'))
    selected = []
    for owner in tree.body:
        if isinstance(owner, ast.ClassDef):
            selected.extend(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name in names)
    assert {n.name for n in selected} == set(names)
    namespace = dict(time=time, copy=copy, Any=object, Optional=NS(__getitem__=lambda _: object),
                     tk=NS(END='end', NORMAL='normal', DISABLED='disabled', TclError=TclError),
                     TclError=TclError, LANE_DRAINING='DRAINING', LANE_BROKEN='BROKEN', LANE_CLOSED='CLOSED', LANE_BUSY='BUSY',
                     LaneState=NS(BROKEN='BROKEN'), NOTICE_SCAN_REFUSAL_TEXT='scan refused')
    namespace.update(extra or {})
    module = ast.Module(body=[ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0), *selected], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(path), 'exec'), namespace)
    return {name: namespace[name] for name in names}


CA_NAMES = {'process_barcode','_process_barcode_entry','_process_barcode_if_current',
            '_scan_entry_admission_block_reason','_hold_or_refuse_entry_scan',
            '_clear_consumed_scan_entry','_set_scan_callback_pending','_refuse_entry_scan','_mark_scan_unaccepted',
            '_hold_scan_during_preflight','_invalidate_pending_scan_callbacks'}
CA = methods('Container_Audit.py', CA_NAMES)
CA_BRIDGE = methods('ca_screen_bridge.py', {'scan','_enter'}, {'ca': NS(NOTICE_SCAN_REFUSAL_TEXT='scan refused')})


def ca_app():
    app = type('CAProbe', (), CA)()
    app.scan_entry, app.root, app.accepted = Entry(), Pump(), []
    app.COLOR_DANGER = app.COLOR_PRIMARY = 'color'
    app.current_tray = NS(master_label_code='')
    app._warning_state_presenter = lambda: NS(state=NS(is_blocking=False))
    for name in ('_notice_scan_take',):
        setattr(app, name, lambda: '')
    for name in ('_reject_residual_tag','_handle_partial_submission_scan','_notice_blocks_scan',
                 '_preflight_context_blocks_mutation','_operator_review_blocks_mutation','_parse_new_format_qr'):
        setattr(app, name, lambda *a, **k: False)
    for name in ('_start_warning_beep','show_status_message','_show_scan_refusal','_update_current_item_label'):
        setattr(app, name, lambda *a, **k: None)
    def accept(raw):
        decision = CA_IDENTITY.decide_product_admission(raw, item_code=ITEM,
            scanned_barcodes=app.accepted, capacity=100, item_code_length=13)
        assert decision.accepted
        app.accepted.append(raw)
    app._process_barcode_logic = accept
    app._preflight_hold_store = lambda: NS()
    app._set_preflight_scan_input_locked = lambda value: (setattr(app,'_preflight_scan_input_locked',value), app._set_scan_callback_pending(False))
    app._preflight_hold_writer = lambda: NS(submit=lambda *args: NS(accepted=False))
    app._is_offline_preflight_hold = lambda _: False
    app._cancel_master_preflight = lambda: None
    return app


CA_RED = ['startup', 'stale_callback', 'delete_exception', 'snapshot_mismatch', 'preflight_writer_refused', 'preflight_writer_failed']


@pytest.mark.parametrize('case', CA_RED)
def test_ca_tk_refusal_then_next_scan_isolated(case):
    app = ca_app()
    app.scan_entry.insert('end', FIRST)
    if case == 'startup':
        app._startup_update_pending = True
    elif case.startswith('preflight'):
        app._master_preflight_pending = True
        if case == 'preflight_writer_failed':
            app._preflight_hold_writer = lambda: NS(submit=lambda work, finish, fail: (app.root.after(0, fail, RuntimeError()), NS(accepted=True))[1])
    app.process_barcode()
    if case == 'stale_callback':
        app._invalidate_pending_scan_callbacks()
    if case == 'delete_exception':
        app.scan_entry.fail_delete = 1
    if case == 'snapshot_mismatch':
        app.scan_entry.configure(state='normal')
        app.scan_entry.insert('end','-EDIT')
    if case == 'preflight_writer_failed':
        # The fixture supplies the exception class used by the actual fail callback.
        CA['_hold_scan_during_preflight'].__globals__['PreflightHoldFull'] = type('PreflightHoldFull', (Exception,), {})
    app.root.drain()
    app._startup_update_pending = app._master_preflight_pending = False
    app._preflight_hold_append_pending = app._preflight_scan_input_locked = False
    app._set_scan_callback_pending(False)
    app.scan_entry.insert('end', SECOND)
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [SECOND]
    assert app.scan_entry.get() == ''


@pytest.mark.parametrize('flag', ['_ui_lane_fault_blocked','_storage_failure_blocked','_storage_failure_current',
    '_local_exchange_checkpoint_pending','_ui_close_requested','_completion_lane_busy',
    '_preflight_scan_input_locked','_phs_label_candidate_pending','_phs_reconciliation_resolve_pending','_phs_label_refresh_pending'])
def test_ca_tk_admission_refusal_consumes(flag):
    app = ca_app()
    app._storage_failure_stop_message = lambda: 'blocked'
    setattr(app, flag, app.current_tray if flag == '_local_exchange_checkpoint_pending' else True)
    app.scan_entry.insert('end', FIRST)
    app.process_barcode()
    app.root.drain()
    assert app.scan_entry.get() == ''
    setattr(app, flag, False if flag != '_local_exchange_checkpoint_pending' else None)
    app._scans_behind_save = []
    app._set_scan_callback_pending(False)
    app.scan_entry.insert('end', SECOND)
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [SECOND]


def test_ca_tk_callback_pending_owns_disabled_value():
    app = ca_app()
    app.scan_entry.insert('end', FIRST)
    app.process_barcode()
    app.scan_entry.insert('end', SECOND)
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [FIRST]
    assert app.scan_entry.get() == ''


def test_ca_tk_preflight_append_pending_keeps_owned_value_until_ack():
    app = ca_app()
    app._master_preflight_pending = True
    callbacks = []
    app._preflight_hold_writer = lambda: NS(submit=lambda work, finish, fail: (callbacks.append(finish), NS(accepted=True))[1])
    app.scan_entry.insert('end', FIRST)
    app.process_barcode()
    assert app.scan_entry.cget('state') == 'disabled'
    app.scan_entry.insert('end', SECOND)
    app.process_barcode()
    callbacks[0]((None, NS(items=[FIRST])))
    assert app.scan_entry.get() == ''
    app._master_preflight_pending = False
    app.scan_entry.insert('end', SECOND)
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [SECOND]


@pytest.mark.parametrize('case', ['startup','modal','scan_answer','band','normal','delete_exception'])
def test_ca_bridge_refusal_then_next_scan_isolated(case):
    app = ca_app()
    bridge = type('CABridgeProbe', (), CA_BRIDGE)()
    bridge.app, bridge.view, bridge._scan_answer, bridge._answer = app, None, None, None
    app._notice_button_captures_scan = lambda: False
    if case == 'startup':
        app._startup_update_pending = True
    elif case == 'modal':
        bridge._answer = object()
    elif case == 'scan_answer':
        bridge._scan_answer = NS(set=lambda value: None)
    elif case == 'band':
        app._notice_blocks_scan = lambda: True
        app._refuse_scan_during_notice = lambda: None
    bridge.scan(FIRST, {})
    app.root.drain()
    if case in {'normal','delete_exception'}:
        app.accepted.clear()
    app._startup_update_pending = False
    bridge._answer = bridge._scan_answer = None
    app._notice_blocks_scan = lambda: False
    if case == 'delete_exception':
        app.scan_entry.insert('end', FIRST)
        app.scan_entry.fail_delete = 1
    response = bridge.scan(SECOND, {})
    if case == 'delete_exception':
        assert response['accepted'] is False
        assert '다시 스캔하세요' in response['message']
        assert app.accepted == []
        bridge.scan(SECOND, {})
    app.root.drain()
    assert app.accepted == [SECOND]


def test_ca_stale_callback_does_not_clear_a_new_scan():
    app = ca_app()
    app._scan_callback_epoch = 1
    app.scan_entry.insert(0, SECOND)
    app._process_barcode_if_current(FIRST, 0)
    assert app.scan_entry.get() == SECOND
    assert app.accepted == []
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [SECOND]


def record_refusals(app):
    notices, sounds = [], []
    def rejected(text):
        notices.append(text)
        app._last_scan_unaccepted_text = text
    app._mark_scan_unaccepted = rejected
    app._start_warning_beep = lambda: sounds.append(True)
    return notices, sounds


@pytest.mark.parametrize('failure', ['delete_exception', 'snapshot_mismatch'])
def test_ca_failed_consumption_discards_snapshot_and_requires_new_scan(failure):
    app = ca_app()
    notices, sounds = record_refusals(app)
    app.scan_entry.insert(0, FIRST)
    app.process_barcode()
    if failure == 'delete_exception':
        app.scan_entry.fail_delete = 1
    else:
        app.scan_entry.value += '_unexpected_tail'
    app.root.drain()
    assert app.scan_entry.get() == ''
    assert app.accepted == []
    assert notices and '다시 스캔하세요' in notices[-1]
    assert sounds
    app.scan_entry.insert(0, SECOND)
    app.process_barcode()
    app.root.drain()
    assert app.accepted == [SECOND]


@pytest.mark.parametrize('transport', ['tk', 'bridge'])
def test_ca_permanent_consumption_failure_blocks_later_enters(transport):
    app = ca_app()
    notices, sounds = record_refusals(app)
    tray = app.current_tray
    app.scan_entry.insert(0, FIRST)
    app.process_barcode()
    app.scan_entry.fail_delete = 100
    app.root.drain()
    assert notices[-1] == '입력 칸 오류 — 프로그램을 다시 켜세요'
    assert app.accepted == []
    app.scan_entry.fail_delete = 0
    app.scan_entry.value = SECOND
    if transport == 'tk':
        app.process_barcode()
    else:
        bridge = type('Bridge', (), CA_BRIDGE)()
        bridge.app, bridge.view, bridge._scan_answer, bridge._answer = app, None, None, None
        app._notice_button_captures_scan = lambda: False
        response = bridge.scan(SECOND, {})
        assert response['accepted'] is False
        assert response['message'] == '입력 칸 오류 — 프로그램을 다시 켜세요'
    app.root.drain()
    assert app.accepted == []
    assert app.current_tray is tray
    assert notices[-1] == '입력 칸 오류 — 프로그램을 다시 켜세요'
    assert len(sounds) >= 2


@pytest.mark.parametrize('failure', ['disabled', 'ignored', 'read_error'])
def test_ca_bridge_requires_verified_empty_entry_before_injection(failure):
    app = ca_app()
    bridge = type('Bridge', (), CA_BRIDGE)()
    bridge.app, bridge.view, bridge._scan_answer, bridge._answer = app, None, None, None
    app._notice_button_captures_scan = lambda: False
    app.scan_entry.insert(0, FIRST)
    get, delete = app.scan_entry.get, app.scan_entry.delete
    if failure == 'disabled':
        app.scan_entry.configure(state='disabled')
    elif failure == 'ignored':
        app.scan_entry.delete = lambda *_args: None
    else:
        def unreadable():
            raise TclError('entry read failed')
        app.scan_entry.get = unreadable
    sounds = []
    app._start_warning_beep = lambda: sounds.append(True)
    response = bridge.scan(SECOND, {})
    app.root.drain()
    assert response['accepted'] is False
    assert '다시 스캔하세요' in response['message']
    assert app.accepted == []
    assert sounds == [True]
    app.scan_entry.get, app.scan_entry.delete = get, delete
    app.scan_entry.configure(state='normal')
    bridge.scan(SECOND, {})
    app.root.drain()
    assert app.accepted == [SECOND]


@pytest.mark.parametrize('case', ['injected_pending','injected_band_result','injected_accepted'])
def test_ca_bridge_injected_notice_then_next_scan_isolated(case):
    app = ca_app()
    bridge = type('CABridgeProbe', (), CA_BRIDGE)()
    bridge.app, bridge.view, bridge._scan_answer, bridge._answer = app, None, None, None
    app._notice_button_captures_scan = lambda: True
    def put(raw): app._probe_notice_text = raw
    def take(): return app.__dict__.pop('_probe_notice_text','')
    app._notice_scan_put, app._notice_scan_take = put, take
    if case == 'injected_pending':
        app._set_scan_callback_pending(True)
    elif case == 'injected_band_result':
        app._warning_state_presenter = lambda: NS(state=NS(is_blocking=True))
        app._operator_review_blocks_mutation = lambda: True
        def refusal(text):
            app._scan_refusal_text, app._scan_refusal_visible = text, True
        app._show_scan_refusal = refusal
    response = bridge.scan(FIRST,{})
    app.root.drain()
    assert response['accepted'] == (case == 'injected_accepted')
    assert app.scan_entry.get() == ''
    app.accepted.clear()
    app._set_scan_callback_pending(False)
    app._warning_state_presenter = lambda: NS(state=NS(is_blocking=False))
    app._operator_review_blocks_mutation = lambda: False
    app._notice_button_captures_scan = lambda: False
    bridge.scan(SECOND,{})
    app.root.drain()
    assert app.accepted == [SECOND]

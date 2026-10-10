"""Stage B: durable names, immutable registration requests and pinned tray owners."""
import copy
import json
import queue
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import Container_Audit as ca
from container_admin_pin import AdminPinClient, AdminPinError
from protected_admin import PROTECTED_ADMIN_OPERATOR_ID, PROTECTED_ADMIN_DISPLAY_NAME
from tests.test_container_admin_pin import make_client
from tests.test_remembered_worker_start import _login, _registry
from tests.test_scanonly_review_regressions import public_scan, _pump_until
from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock, COMPACT_QR, ITEM
from worker_roster import (WorkerRoster, CONTRACT_VERSION_V2, STAGE_A, normalize_registration_name,
                           registration_enabled, worker_choice_label)

pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


def worker(name='tester', *, worker_id=None, number=1, status='ACTIVE'):
    return {'worker_id': worker_id or str(uuid.uuid4()), 'display_name': name,
            'worker_number': number, 'status': status}


def snapshot(*workers, version=1, links=()):
    return {'ok': True, 'contract_version': CONTRACT_VERSION_V2, 'authority_scope_id': 'site-1',
            'version': version, 'unchanged': False, 'workers': list(workers), 'temp_links': list(links)}


def roster(tmp_path, *workers):
    result = WorkerRoster(tmp_path / 'roster.json', 'site-1')
    if workers:
        result.apply(snapshot(*workers), requested_version=None)
    return result


def acknowledgement(body, *, name=None, version=2, worker_id=None):
    row = worker(name or body['display_name'], worker_id=worker_id or body.get('existing_worker_id'))
    link = {'temp_uuid': body['temp_uuid'], 'worker_id': row['worker_id'], 'worker_number': 1} if body['mode'] == 'create' else None
    return {'ok': True, 'contract_version': CONTRACT_VERSION_V2, 'authority_scope_id': 'site-1',
            'request_id': body['request_id'], 'version': version, 'worker': row, 'temp_link': link}


def application(flow, tmp_path):
    app = flow(transition=False)
    _login(app, _registry(tmp_path / 'workers.json'), tmp_path)
    app.worker_roster = roster(tmp_path / 'roster')
    app._refresh_worker_roster = lambda: None
    return app


@pytest.mark.parametrize('value,expected', [
    ('  김  ', '김'), (' Nguyen\u00a0  Van ', 'Nguyen Van'), ('e\u0301', 'é'),
    ('김' * 64, '김' * 64), ('😀' * 64, '😀' * 64),
])
def test_registration_normalizes_nfc_spaces_and_accepts_64_codepoints(value, expected):
    assert normalize_registration_name(value) == expected


@pytest.mark.parametrize('value', ['', '  ', 'x' * 65, '123456', PROTECTED_ADMIN_OPERATOR_ID, PROTECTED_ADMIN_DISPLAY_NAME,
    '=a', '+a', '-a', '@a', 'a/b', 'a\\b', 'a\x00b', 'a\nb', 'a\u200bb', 'a\ud800b', 'a\u2028b'])
def test_registration_rejects_unsafe_or_protected_admin_input(tmp_path, value):
    store = roster(tmp_path)
    with pytest.raises(ValueError):
        store.register_local(value)
    assert store.local['sequence'] == 0 and not store.local_path.exists()


@pytest.mark.parametrize('answer,expected', [
    ({}, False), ({'capabilities': {'worker_roster_v2': {'stage_b': True}}}, False),
    ({'capabilities': {'worker_roster_v2': {'stage_b': True, 'temporary_identity_ingest': True}}}, True),
    ({'capabilities': {'worker_roster_v2': {'stage_b': 1, 'temporary_identity_ingest': True}}}, False),
    ({'data': {'capabilities': {}, 'capability_ids': ['worker_roster_v2_stage_b']}}, True),
])
def test_register_gate_accepts_both_true_signals_or_id(answer, expected):
    assert registration_enabled(answer) is expected
    assert STAGE_A is False


def test_local_worker_request_and_sequence_survive_restart_together(tmp_path):
    store = roster(tmp_path)
    local = store.register_local(' 새 이름 ')
    body, = store.pending_requests()
    envelope = json.loads(store.local_path.read_text(encoding='utf-8'))
    assert envelope['sequence'] == local['local_sequence'] == 1
    assert body['temp_uuid'] == local['worker_id']
    assert set(body) == {'mode', 'authority_scope_id', 'request_id', 'display_name', 'action_at', 'temp_uuid'}
    assert worker_choice_label(local) == '새 이름 #임시1'
    restarted = WorkerRoster(store.path, 'site-1')
    assert restarted.pending_requests() == [body]
    assert restarted.active_workers() == store.active_workers()


def test_two_roster_instances_preserve_each_others_registration_and_ack(tmp_path):
    first = roster(tmp_path)
    second = WorkerRoster(first.path, 'site-1')
    one = first.register_local('one')
    two = second.register_local('two')
    requests = second.pending_requests()
    assert [row['local_sequence'] for row in second.local['workers']] == [1, 2]
    reply_one = acknowledgement(requests[0])
    reply_two = acknowledgement(requests[1])
    reply_two['worker']['worker_number'] = reply_two['temp_link']['worker_number'] = 2
    first.apply_registration(requests[0], reply_one)
    second.apply_registration(requests[1], reply_two)
    restarted = WorkerRoster(first.path, 'site-1')
    assert restarted.local['sequence'] == 2 and not restarted.pending_requests()
    assert [item['body'] for item in restarted.local['requests']] == requests
    assert restarted.same_person(one['worker_id'], reply_one['worker']['worker_id'])
    assert restarted.same_person(two['worker_id'], reply_two['worker']['worker_id'])


def test_fsync_failure_keeps_input_unselectable_and_other_names_usable(flow, windows, tmp_path, monkeypatch):
    app = application(flow, tmp_path)
    app._set_worker_entry_value('tester')
    original = app.worker_entry.get()
    monkeypatch.setattr('storage_utils.os.fsync', lambda fd: (_ for _ in ()).throw(OSError('synthetic disk failure')))
    with pytest.raises(OSError):
        app._register_worker_name('새 이름')
    assert app.worker_entry.get() == original
    assert app._worker_selection_names() == ['tester']
    assert app.worker_roster.local['workers'] == []
    assert not app.worker_roster.local_path.exists() and windows == []


@pytest.mark.parametrize('scenario', ['failure', 'mapping'])
def test_registration_dialog_preserves_input_on_failure_and_identity_on_mapping(flow, windows, tmp_path, monkeypatch, scenario):
    app = application(flow, tmp_path)
    if scenario == 'mapping':
        app._register_worker_name('동명')
    variables, widgets = [], []
    class Variable:
        def __init__(self):
            self.value = ''
            variables.append(self)
        def get(self): return self.value
        def set(self, value): self.value = value
    class Widget:
        def __init__(self, *args, **kwargs):
            self.options, self.destroyed = kwargs, False
            self.value = ''
            widgets.append(self)
        def get(self): return self.value
        def set(self, value): self.value = value
        def pack(self, **kwargs): pass
        def pack_forget(self): pass
        def bind(self, *args): pass
        def focus_set(self): pass
        def winfo_exists(self): return not self.destroyed
        def lift(self): pass
        def grab_set(self): pass
        def title(self, title): pass
        def transient(self, parent): pass
        def configure(self, **kwargs): self.options.update(kwargs)
        def destroy(self): self.destroyed = True
    monkeypatch.setattr(ca.tk, 'StringVar', Variable)
    monkeypatch.setattr(ca.tk, 'Toplevel', Widget)
    for name in ('Frame', 'Label', 'Entry', 'Combobox', 'Button'):
        monkeypatch.setattr(ca.ttk, name, Widget)
    if scenario == 'failure':
        app._register_worker_name = lambda *args, **kwargs: (_ for _ in ()).throw(OSError('synthetic save failure'))
    app.register_worker_from_login()
    count = len(widgets)
    app.register_worker_from_login()
    assert len(widgets) == count
    variables[0].set('새 이름' if scenario == 'failure' else '동명')
    button, = [widget for widget in widgets if widget.options.get('text') == '등록']
    button.options['command']()
    if scenario == 'failure':
        assert variables[0].get() == '새 이름' and not widgets[0].destroyed
        assert any('입력은 남아' in widget.options.get('text', '') for widget in widgets)
    else:
        assert not widgets[0].destroyed
        request, = app.worker_roster.pending_requests()
        answer = acknowledgement(request, name='동명_1')
        app.worker_roster.apply_registration(request, answer)
        same, = [widget for widget in widgets if widget.options.get('text') == '같은 사람']
        same.options['command']()
        assert widgets[0].destroyed
        returned, = app.worker_roster.pending_requests()
        assert returned['mode'] == 'return' and returned['existing_worker_id'] == answer['worker']['worker_id']
        assert len(app.worker_roster.local['workers']) == 1
    assert windows == []


def test_damaged_envelope_is_preserved_and_never_replaced_with_fresh_ids(tmp_path):
    store = roster(tmp_path, worker())
    store.register_local('new')
    damaged = b'{broken registration bytes'
    store.local_path.write_bytes(damaged)
    restarted = WorkerRoster(store.path, 'site-1')
    assert restarted.local_blocked
    preserved, = store.path.parent.glob(store.local_path.name + '.bad-*')
    assert preserved.read_bytes() == damaged
    with pytest.raises(ValueError):
        restarted.register_local('another')
    assert not restarted.local_path.exists()
    assert WorkerRoster(store.path, 'site-1').local_blocked
    known = worker('web name')
    restarted.apply(snapshot(known, version=3), requested_version=None)
    assert restarted.active_workers() == [known]
    assert WorkerRoster(store.path, 'site-1').active_workers() == [known]


def test_signed_v2_queries_and_replays_use_original_body_and_fresh_nonce(tmp_path, monkeypatch):
    store = roster(tmp_path)
    store.register_local('tester')
    body, = store.pending_requests()
    reply = acknowledgement(body)
    calls = []
    def transport(path, raw, headers):
        calls.append((path, json.loads(raw), headers['X-Producer-Nonce']))
        return (200, json.dumps(snapshot()).encode()) if path.endswith('/query') else (201, json.dumps(reply).encode())
    client = make_client(monkeypatch, transport)
    client.query_roster_v2(authority_scope_id='site-1')
    client.register_roster(body)
    client.register_roster(body)
    assert calls[0][:2] == ('/api/worker-roster/v2/query', {'authority_scope_id': 'site-1'})
    assert calls[1][1] == calls[2][1] == body
    assert calls[1][2] != calls[2][2]
    for field in ('current_pin', 'approved', 'producer_install_id'):
        with pytest.raises(AdminPinError):
            client.register_roster({**body, field: True})
    assert len(calls) == 3


@pytest.mark.parametrize('status,code', [(503, 'ROSTER_V2_REGISTER_DISABLED'), (429, 'RATE_LIMITED'), (500, 'INTERNAL_ERROR')])
def test_roster_client_preserves_unknown_error_code_status_and_outbox(tmp_path, monkeypatch, status, code):
    store = roster(tmp_path)
    store.register_local('tester')
    body, = store.pending_requests()
    client = make_client(monkeypatch, lambda *args: (status, json.dumps({'ok': False, 'error': {'code': code}}).encode()))
    with pytest.raises(AdminPinError) as caught:
        client.register_roster(body)
    assert caught.value.status == status and caught.value.code == code and caught.value.unknown
    store.apply_registration(body, error=caught.value)
    assert store.pending_requests() == [body]
    assert WorkerRoster(store.path, 'site-1').pending_requests() == [body]


def test_ack_save_failure_and_lost_ack_recover_mapping_without_regenerating_request(tmp_path, monkeypatch):
    store = roster(tmp_path)
    local = store.register_local('tester')
    body, = store.pending_requests()
    reply = acknowledgement(body, name='tester_1')
    with monkeypatch.context() as patcher:
        patcher.setattr('worker_roster.atomic_write_json', lambda *args, **kwargs: (_ for _ in ()).throw(OSError('lost save')))
        with pytest.raises(OSError):
            store.apply_registration(body, reply)
    assert store.pending_requests() == [body]
    assert store.resolved_id(local['worker_id']) == local['worker_id']
    restarted = WorkerRoster(store.path, 'site-1')
    restarted.apply(snapshot(reply['worker'], links=[reply['temp_link']], version=2), requested_version=None)
    assert not restarted.pending_requests()
    assert restarted.resolved_id(local['worker_id']) == reply['worker']['worker_id']
    assert worker_choice_label(restarted.active_workers()[0]) == 'tester_1 #1'
    assert restarted.local['requests'][0]['body'] == body


def test_same_pending_name_keeps_one_create_and_durable_dependent_return(tmp_path):
    store = roster(tmp_path)
    first = store.register_local('tester')
    create, = store.pending_requests()
    same = store.register_local('tester', existing_worker_id=first['worker_id'])
    assert same['worker_id'] == first['worker_id']
    assert store.pending_requests() == [create]
    intent = copy.deepcopy(store.local['requests'][1])
    assert intent['body'] is None and intent['depends_on'] == create['request_id']
    restarted = WorkerRoster(store.path, 'site-1')
    reply = acknowledgement(create)
    restarted.apply_registration(create, reply)
    returned, = restarted.pending_requests()
    assert returned['mode'] == 'return' and 'temp_uuid' not in returned
    assert returned['existing_worker_id'] == reply['worker']['worker_id']
    assert returned['request_id'] == intent['request_id']
    assert returned['action_at'] == intent['intent']['action_at']
    assert WorkerRoster(store.path, 'site-1').pending_requests() == [returned]


def test_same_central_name_returns_existing_uuid_and_different_name_creates(tmp_path):
    original = worker('tester')
    store = roster(tmp_path, original)
    assert store.duplicate_workers(' tester ') == [original]
    with pytest.raises(ValueError):
        store.register_local('tester')
    same = store.register_local('tester', existing_worker_id=original['worker_id'])
    returned, = store.pending_requests()
    assert same['worker_id'] == returned['existing_worker_id'] == original['worker_id']
    assert returned['mode'] == 'return' and 'temp_uuid' not in returned
    different = store.register_local('testerB')
    assert different['worker_id'] != original['worker_id']
    assert len(store.active_workers()) == 2


@pytest.mark.parametrize('code', ['REQUEST_CONFLICT', 'TEMP_ID_CONFLICT'])
def test_conflict_never_reissues_identity_and_mapping_preserves_review_until_name_matches(tmp_path, code):
    store = roster(tmp_path)
    local = store.register_local('tester')
    body, = store.pending_requests()
    store.apply_registration(body, error=AdminPinError(code, status=409))
    assert not store.pending_requests() and store.active_worker(worker_id=local['worker_id'])
    reply = acknowledgement(body, name='different')
    store.apply(snapshot(reply['worker'], links=[reply['temp_link']], version=3), requested_version=None)
    assert store.local['requests'][0]['state'] == 'REVIEW'
    assert store.local['requests'][0]['error'] == code
    assert store.local['requests'][0]['body'] == body
    store.apply(snapshot({**reply['worker'], 'display_name': 'tester'}, links=[reply['temp_link']], version=4), requested_version=3)
    assert store.local['requests'][0]['state'] == 'ACKED'
    assert store.local['requests'][0]['error'] == code


def test_new_server_disabled_status_wins_over_pending_return_and_picker_hidden_is_ignored(tmp_path):
    original = worker('tester')
    store = roster(tmp_path, {**original, 'picker_hidden': True})
    assert store.active_workers() == [original] and STAGE_A is False
    store.register_local('tester', existing_worker_id=original['worker_id'])
    store.apply(snapshot({**original, 'status': 'DISABLED'}, version=2), requested_version=1)
    assert store.local['requests'][0]['state'] == 'TERMINAL'
    assert not store.pending_requests() and not store.active_workers()


@pytest.mark.parametrize('code,status', [('WORKER_DISABLED', 403), ('WORKER_NOT_FOUND', 404)])
def test_rejected_return_is_terminal_and_not_selectable(tmp_path, code, status):
    original = worker()
    store = roster(tmp_path, original)
    store.register_local('tester', existing_worker_id=original['worker_id'])
    request, = store.pending_requests()
    store.apply_registration(request, error=AdminPinError(code, status=status))
    assert store.local['requests'][0]['state'] == 'TERMINAL'
    assert not store.active_workers() and not store.pending_requests()
    store.apply(snapshot(original, version=2), requested_version=1)
    assert store.active_workers() == [original]
    assert store.local['requests'][0]['state'] == 'TERMINAL' and not store.pending_requests()


def test_unsafe_central_name_never_resurrects_through_temporary_alias(tmp_path):
    store = roster(tmp_path)
    local = store.register_local('tester')
    request, = store.pending_requests()
    reply = acknowledgement(request)
    store.apply(snapshot({**reply['worker'], 'display_name': 'unsafe/name'}, links=[reply['temp_link']], version=2), requested_version=None)
    assert store.same_person(local['worker_id'], reply['worker']['worker_id'])
    assert not store.active_workers()
    assert not WorkerRoster(store.path, 'site-1').active_workers()


def test_older_query_keeps_new_status_but_saves_immutable_temp_mapping(tmp_path):
    store = roster(tmp_path)
    local = store.register_local('tester')
    body, = store.pending_requests()
    reply = acknowledgement(body)
    store.apply(snapshot({**reply['worker'], 'status': 'DISABLED'}, version=4), requested_version=None)
    store.apply(snapshot(reply['worker'], links=[reply['temp_link']], version=2), requested_version=None)
    assert store.known_version == 4 and not store.active_workers()
    assert store.same_person(local['worker_id'], reply['worker']['worker_id'])
    original = store.local_path.read_bytes()
    with pytest.raises(ValueError):
        store.apply(snapshot(links=[{**reply['temp_link'], 'worker_id': str(uuid.uuid4())}], version=5), requested_version=4)
    assert store.local_path.read_bytes() == original


@pytest.mark.parametrize('future', [False, True])
def test_invalid_request_is_item_review_except_future_action_at(tmp_path, future):
    store = roster(tmp_path)
    if future:
        import datetime
        real = datetime.datetime
        class FutureClock(real):
            @classmethod
            def now(cls, tz=None):
                return real.now(tz) + datetime.timedelta(minutes=10)
        with patch('worker_roster.datetime.datetime', FutureClock):
            store.register_local('tester')
    else:
        store.register_local('tester')
    request, = store.pending_requests()
    store.apply_registration(request, error=AdminPinError('INVALID_REQUEST', status=400))
    assert bool(store.pending_requests()) is future
    assert store.local['requests'][0]['body'] == request


@pytest.mark.parametrize('gate', [False, True])
def test_local_registration_and_wire_identity_are_capability_gated_without_blocking_selection(flow, windows, tmp_path, gate):
    app = application(flow, tmp_path)
    local = app._register_worker_name('new')
    app._worker_record_identity_enabled = True  # v1 alone cannot advertise temporary identity support.
    app._worker_roster_stage_b = gate
    assert app._ensure_worker_login_name('new #임시1') == 'new'
    app.worker_name = 'new'
    context = app._worker_record_context()
    assert context['worker_id'] == local['worker_id'] and context['enabled'] is gate
    assert '나중에' in app._worker_roster_notice_text() and windows == []


def test_mapping_affects_only_next_tray_and_recovers_old_owner_without_rewriting_saved_command(flow, windows, tmp_path):
    app = application(flow, tmp_path)
    local = app._register_worker_name('testerB')
    app._worker_roster_stage_b = app._worker_record_identity_enabled = True
    app.start_work()
    public_scan(app, COMPACT_QR + '|QT=3')
    public_scan(app, ITEM + '-SERIAL-001')
    original = app._current_tray_state_snapshot()
    from transfer_seal import TransferSealStore
    store = TransferSealStore(tmp_path / 'pinned.db', owner_thread_id_provider=threading.get_ident)
    intent = store.prepare(master_label=COMPACT_QR, source_identity={'item_id': ITEM}, item_id=ITEM,
        operator='testerB', scanned_barcodes=['part'], scan_context={
            'worker_record': app._worker_record_context(),
            'worker_id': local['worker_id'], 'worker_name_snapshot': 'testerB'})
    store.mark_scan_completion_projected(intent['intent_id'])
    bound = store.bind_command(intent['intent_id'], {'idempotency_key': intent['idempotency_key'], 'payload': {'item_id': ITEM}})
    parked = app._parked_store()
    parked_path = parked.save_state(original, worker_name='testerB', master_label=original['master_label_code'])
    parked_bytes = parked_path.read_bytes()
    body, = app.worker_roster.pending_requests()
    reply = acknowledgement(body, name='testerB_1')
    app.worker_roster.apply_registration(body, reply)
    app.worker_roster = WorkerRoster(app.worker_roster.path, app.worker_roster.authority_scope_id)
    app._selected_roster_id = reply['worker']['worker_id']
    app._restore_tray_from_state(original)
    assert app._owns_worker_record(original)
    assert app._current_tray_state_snapshot()['worker_id'] == local['worker_id']
    assert app._worker_record_context()['worker_name_snapshot'] == 'testerB'
    reopened = TransferSealStore(store.db_path).load(intent['intent_id'])
    assert reopened['command_json'] == bound['command_json'] and reopened['command_hash'] == bound['command_hash']
    assert json.loads(reopened['command_json'])['payload']['worker_identity']['worker_id'] == local['worker_id']
    assert [row.path for row in parked.scan_for_worker('testerB_1', strict=True,
        worker_id=reply['worker']['worker_id'], worker_id_aliases=app.worker_roster.identity_aliases(reply['worker']['worker_id']))] == [parked_path]
    assert parked_path.read_bytes() == parked_bytes
    app.current_tray = ca.TraySession()
    assert app._roster_allows_new_tray()
    public_scan(app, COMPACT_QR.replace('LBL-COMPACT-001', 'LBL-COMPACT-002') + '|QT=3')
    assert app.current_tray.worker_id == reply['worker']['worker_id']
    assert app.current_tray.worker_name_snapshot == 'testerB_1'
    assert windows == []


@pytest.mark.parametrize('status,expected_count', [(400, 2), (409, 2), (500, 2), (401, 1), (403, 1), (429, 1), (503, 1)])
def test_item_errors_continue_and_installation_errors_stop_only_this_send_round(flow, windows, tmp_path, monkeypatch, status, expected_count):
    app = application(flow, tmp_path)
    app._register_worker_name('one')
    app._register_worker_name('two')
    calls = []
    def transport(path, body, headers):
        if path.endswith('/query'):
            return 200, json.dumps(snapshot()).encode()
        calls.append(json.loads(body))
        if len(calls) == 1:
            return status, json.dumps({'ok': False, 'error': {'code': 'ROSTER_V2_REGISTER_DISABLED' if status == 503 else 'INVALID_REQUEST'}}).encode()
        return 201, json.dumps(acknowledgement(json.loads(body))).encode()
    app._admin_pin_client = make_client(monkeypatch, transport)
    monkeypatch.setattr(ca, 'logistics_transfer_client_from_env', lambda **kw: SimpleNamespace(get_capabilities=lambda:
        {'capability_ids': ['worker_roster_v2_stage_b']}))
    ca.ContainerAudit._refresh_worker_roster(app)
    app._roster_thread.join(3)
    assert not app._roster_thread.is_alive()
    _pump_until(app.root, lambda: getattr(app, '_roster_refresh_job', None) is not None)
    assert len(calls) == expected_count
    assert len(app.worker_roster.local['requests']) == 2
    assert app._worker_selection_names() and windows == []
    if status == 503:
        assert app._worker_roster_stage_b is False
        assert app.worker_roster.local['requests'][0]['state'] == 'PENDING'


def test_late_login_result_cannot_apply_ack_or_change_current_gate(flow, windows, tmp_path):
    app = application(flow, tmp_path)
    app._register_worker_name('new')
    request, = app.worker_roster.pending_requests()
    before = app.worker_roster.local_path.read_bytes()
    app._admin_pin_login_epoch = 'new-login'
    app._roster_attempt = 'attempt'
    replies = queue.Queue()
    replies.put({'roster_answer': snapshot(worker()), 'stage_b': True, 'identity_enabled': True,
                 'registrations': [(request, acknowledgement(request), None)]})
    app._poll_worker_roster(replies, 'attempt', 'old-login', None, expected_roster=app.worker_roster)
    assert app.worker_roster.local_path.read_bytes() == before
    assert app.worker_roster.pending_requests() == [request]
    assert getattr(app, '_worker_roster_stage_b', False) is False and windows == []


def test_gate_off_never_calls_register_but_keeps_web_names_and_local_queue(flow, windows, tmp_path, monkeypatch):
    app = application(flow, tmp_path)
    app._register_worker_name('new')
    original = app.worker_roster.pending_requests()
    calls = []
    remote = worker('web name')
    def transport(path, body, headers):
        calls.append(path)
        return 200, json.dumps(snapshot(remote)).encode()
    app._admin_pin_client = make_client(monkeypatch, transport)
    monkeypatch.setattr(ca, 'logistics_transfer_client_from_env', lambda **kw: SimpleNamespace(get_capabilities=lambda: {}))
    ca.ContainerAudit._refresh_worker_roster(app)
    app._roster_thread.join(3)
    _pump_until(app.root, lambda: getattr(app, '_roster_refresh_job', None) is not None)
    assert calls == ['/api/worker-roster/v2/query']
    assert app.worker_roster.pending_requests() == original
    assert set(app._worker_selection_names()) == {'web name #1', 'new #임시1'}
    assert windows == []


def test_unsupported_v2_query_falls_back_to_v1_even_for_html_404(flow, windows, tmp_path, monkeypatch):
    from tests.test_worker_roster import response, row
    app = application(flow, tmp_path)
    calls = []
    original = row('web name')
    def transport(path, body, headers):
        calls.append(path)
        if path == '/api/worker-roster/v2/query':
            return 404, b'<html>Not found</html>'
        return 200, json.dumps(response(original)).encode()
    app._admin_pin_client = make_client(monkeypatch, transport)
    monkeypatch.setattr(ca, 'logistics_transfer_client_from_env', lambda **kw: SimpleNamespace(get_capabilities=lambda: {}))
    ca.ContainerAudit._refresh_worker_roster(app)
    app._roster_thread.join(3)
    _pump_until(app.root, lambda: getattr(app, '_roster_refresh_job', None) is not None)
    assert calls == ['/api/worker-roster/v2/query', '/api/worker-roster/v1/query']
    assert app._worker_selection_names() == ['web name'] and windows == []


def test_slow_registration_does_not_hold_admission_or_delay_ordered_scans(flow, windows, tmp_path, monkeypatch):
    app = application(flow, tmp_path)
    app._register_worker_name('new')
    app.start_work()
    public_scan(app, COMPACT_QR + '|QT=3')
    entered, release = threading.Event(), threading.Event()
    def transport(path, raw, headers):
        body = json.loads(raw)
        if path.endswith('/query'):
            return 200, json.dumps(snapshot()).encode()
        entered.set()
        assert release.wait(5)
        return 201, json.dumps(acknowledgement(body)).encode()
    app._admin_pin_client = make_client(monkeypatch, transport)
    monkeypatch.setattr(ca, 'logistics_transfer_client_from_env', lambda **kw: SimpleNamespace(get_capabilities=lambda:
        {'capability_ids': ['worker_roster_v2_stage_b']}))
    try:
        ca.ContainerAudit._refresh_worker_roster(app)
        assert entered.wait(2)
        started = time.monotonic()
        for suffix in ('001', '002'):
            public_scan(app, ITEM + '-SERIAL-' + suffix)
        assert time.monotonic() - started < 1
        state = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text(encoding='utf-8'))
        assert state['scanned_barcodes'] == [ITEM + '-SERIAL-001', ITEM + '-SERIAL-002']
    finally:
        release.set()
        app._roster_thread.join(3)
    _pump_until(app.root, lambda: getattr(app, '_roster_refresh_job', None) is not None)
    assert windows == []

"""Same-label reprint liveness and screen-only rejected printer identity."""
import json
import threading
from types import SimpleNamespace

import pytest

import phs_label_workflow as module
from tests.test_print_submission_budget import (
    FakeCentral, FakeReconciliationServer, ITEM, _resolution, _target_candidate,
    _tray, app, coordinator, hardware, pump, reconcile, wait_for,
)


BUSY_NOTICE = '이전 인쇄가 아직 프린터 대기열에 있습니다 — 프린터 대기열을 확인한 뒤 다시 누르세요'


def setup_ui(app, root, monkeypatch, reconciliation, *, confirmed=False):
    tray = _tray()
    app.current_tray = tray
    app._reject_mutation_during_preflight_hold = lambda: False
    app._phs_label_exchange_pending = False
    app._phs_label_refresh_pending = False
    app.phs_label_reprint_confirm_var = SimpleNamespace(get=lambda: confirmed, set=lambda value: None)
    printer = module.WindowsGDIPhysicalLabelPrinter()
    if reconciliation:
        client = FakeReconciliationServer(_resolution('SPLIT'))
        flow = reconcile(root, client, printer=printer)
        context = flow.reconciliation.resolve(client.resolution['scan']['active_qr_payload'])
        app._phs_reconciliation_context = context
        execute = lambda **kw: flow.reconciliation.execute(context, **kw)
        click = app._execute_phs_reconciliation_exchange
    else:
        client = FakeCentral()
        flow = coordinator(root, client, printer)
        app._phs_label_exchange_available_for_tray = lambda: True
        app._selected_phs_label_candidate = _target_candidate
        execute = lambda **kw: flow.execute_single(tray, _target_candidate(), **kw)
        click = app._execute_selected_phs_label_exchange
    app.phs_label_exchange_coordinator = flow
    return flow, client, tray, execute, click


@pytest.mark.parametrize('reconciliation', [False, True])
def test_alive_attempt_blocks_confirmed_reprint_but_other_print_scan_and_later_retry_continue(app, tmp_path, monkeypatch, reconciliation):
    release = threading.Event()
    calls, entered = hardware(monkeypatch, release=release)
    monkeypatch.setattr(module, 'PRINT_SUBMIT_TIMEOUT_SECONDS', 0.02)
    scan_tray = app.current_tray
    flow, client, tray, execute, click = setup_ui(app, tmp_path, monkeypatch, reconciliation, confirmed=True)
    acknowledgements = []
    complete = client.complete_phs_label_print
    def record_ack(*args, **kwargs):
        acknowledgements.append(kwargs)
        return complete(*args, **kwargs)
    monkeypatch.setattr(client, 'complete_phs_label_print', record_ack)
    notices = []
    app.show_status_message = lambda message, *a, **kw: notices.append(message)
    before = (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
    try:
        first = execute()
        assert first.error_code == 'PHS_LOCAL_PRINT_UNKNOWN' and entered.is_set()
        state = flow.journal.load()
        progress = next(value for value in state['targets'].values() if value.get('status') == 'LOCAL_PRINT_STARTING') if reconciliation else state
        key = progress['print_idempotency_key']
        label_id = next(label_id for label_id, value in state['targets'].items() if value is progress) if reconciliation else state['target_label']['label_id']
        submission_key = (state['exchange_id'], label_id)
        click()
        lane = app._ui_task_lane()
        pump(app, lambda: not app._phs_label_exchange_pending and not lane.is_busy())
        assert BUSY_NOTICE in notices
        assert sum(call[0] == 'StartDocW' for call in calls) == 1
        assert not acknowledgements
        assert before == (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
        state = flow.journal.load()
        pending = next(value for value in state['targets'].values() if value.get('status') == 'LOCAL_PRINT_STARTING') if reconciliation else state
        assert pending['print_idempotency_key'] == key and pending['print_result'] == 'UNKNOWN'
        # The same identity is protected across adapter instances too.
        with pytest.raises(module.PHSPrintUnknown, match='이전 인쇄가 아직'):
            module.WindowsGDIPhysicalLabelPrinter().print_png(progress['rendered_path'], document_name='retry', submission_key=submission_key)
        normal_calls, _ = hardware(monkeypatch)
        monkeypatch.setattr(module, 'PRINT_SUBMIT_TIMEOUT_SECONDS', 1)
        evidence = module.WindowsGDIPhysicalLabelPrinter().print_png(progress['rendered_path'], document_name='other', submission_key=(state['exchange_id'], label_id + '-other'))
        assert evidence.spool_job_id == 73 and sum(call[0] == 'StartDocW' for call in normal_calls) == 1
        app.current_tray = scan_tray
        app._process_barcode_logic(ITEM + '-next')
        pump(app, lambda: len(scan_tray.scanned_barcodes) == 1 and not lane.is_busy())
        assert scan_tray.scanned_barcodes == [ITEM + '-next']
        release.set()
        wait_for(lambda: not any(thread in module.PRINT_SUBMISSION_THREADS and thread.is_alive() for thread in threading.enumerate()))
        assert flow.journal.load()['status'] != 'COMMITTED' and not acknowledgements
        retry = execute(confirm_ambiguous_reprint=True)
        assert retry.success and retry.status == 'COMMITTED'
        assert acknowledgements and all(ack['succeeded'] for ack in acknowledgements)
        assert sum(call[0] == 'StartDocW' for call in calls) == 1
    finally:
        release.set()
        wait_for(lambda: not any(thread in module.PRINT_SUBMISSION_THREADS and thread.is_alive() for thread in threading.enumerate()))


@pytest.mark.parametrize('reconciliation', [False, True])
def test_new_attempt_is_blocked_for_same_label_until_previous_submission_finishes(app, tmp_path, monkeypatch, reconciliation):
    release = threading.Event()
    calls, entered = hardware(monkeypatch, release=release)
    monkeypatch.setattr(module, 'PRINT_SUBMIT_TIMEOUT_SECONDS', 0.02)
    flow, client, tray, execute, click = setup_ui(app, tmp_path, monkeypatch, reconciliation, confirmed=True)
    requests, notices = [], []
    request = client.request_phs_label_print
    def record_request(*args, **kwargs):
        requests.append(kwargs)
        response = request(*args, **kwargs)
        if not reconciliation:
            response['print_attempt']['print_attempt_id'] = f'PRINT-{len(requests)}'
        return response
    monkeypatch.setattr(client, 'request_phs_label_print', record_request)
    app.show_status_message = lambda message, *a, **kw: notices.append(message)
    before = (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
    try:
        first = execute()
        assert first.error_code == 'PHS_LOCAL_PRINT_UNKNOWN' and entered.is_set()
        state = flow.journal.load()
        label_id = next(label_id for label_id, value in state['targets'].items() if value.get('status') == 'LOCAL_PRINT_STARTING') if reconciliation else state['target_label']['label_id']
        progress = state['targets'][label_id] if reconciliation else state
        first_key, first_attempt = progress['print_idempotency_key'], progress['print_attempt_id']
        assert progress['print_attempt_no'] == 1
        # Inject a recovered failure while its driver submission is still alive.
        client.complete_phs_label_print(first_attempt, authority_scope_id=state['authority_scope_id'], succeeded=False)
        progress['status'] = 'PRINT_FAILED'
        state['status'] = 'PRINT_FAILED'
        flow.journal.save(state)
        click()
        lane = app._ui_task_lane()
        pump(app, lambda: not app._phs_label_exchange_pending and not lane.is_busy())
        pending_state = flow.journal.load()
        pending = pending_state['targets'][label_id] if reconciliation else pending_state
        assert pending['print_attempt_no'] == 2 and pending['print_attempt_id'] != first_attempt
        assert pending['print_idempotency_key'] != first_key
        assert requests[0]['idempotency_key'] == first_key
        assert requests[1]['idempotency_key'] == pending['print_idempotency_key']
        assert BUSY_NOTICE in notices
        assert sum(call[0] == 'StartDocW' for call in calls) == 1
        assert pending['status'] == 'LOCAL_PRINT_STARTING' and pending['print_result'] == 'UNKNOWN'
        assert before == (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
        assert not (any(ack['succeeded'] for ack in client.complete_calls) if not reconciliation else any(value['state'] == 'SUCCEEDED' for value in client._attempts.values()))
        normal_calls, _ = hardware(monkeypatch)
        monkeypatch.setattr(module, 'PRINT_SUBMIT_TIMEOUT_SECONDS', 1)
        evidence = module.WindowsGDIPhysicalLabelPrinter().print_png(
            pending['rendered_path'], document_name='other label',
            submission_key=(state['exchange_id'], label_id + '-other'))
        assert evidence.spool_job_id == 73 and sum(call[0] == 'StartDocW' for call in normal_calls) == 1
        release.set()
        wait_for(lambda: not any(thread in module.PRINT_SUBMISSION_THREADS and thread.is_alive() for thread in threading.enumerate()))
        unchanged = flow.journal.load()
        unchanged = unchanged['targets'][label_id] if reconciliation else unchanged
        assert unchanged['print_idempotency_key'] == pending['print_idempotency_key'] and unchanged['print_result'] == 'UNKNOWN'
        retry = execute(confirm_ambiguous_reprint=True)
        assert retry.success and retry.status == 'COMMITTED'
        assert len([request for request in requests if request['label_id'] == label_id]) == 2
        completed = flow.journal.load()
        completed = completed['targets'][label_id] if reconciliation else completed
        assert completed['print_attempt_no'] == 2 and completed['print_idempotency_key'] == pending['print_idempotency_key']
        expected_jobs = 3 if reconciliation else 2  # Other label plus remaining exchange targets.
        assert sum(call[0] == 'StartDocW' for call in normal_calls) == expected_jobs
        assert sum(call[0] == 'StartDocW' for call in calls) == 1
    finally:
        release.set()
        wait_for(lambda: not any(thread in module.PRINT_SUBMISSION_THREADS and thread.is_alive() for thread in threading.enumerate()))


@pytest.mark.parametrize('reconciliation', [False, True])
@pytest.mark.parametrize('paper_rejected', [False, True])
def test_rejected_printer_name_is_shown_only_on_screen_not_in_records(app, tmp_path, monkeypatch, reconciliation, paper_rejected):
    private_name = 'private-default-label'
    calls, _ = hardware(monkeypatch, name=private_name, port='USB001' if paper_rejected else 'PORTPROMPT:', paper_rejected=paper_rejected)
    flow, client, tray, execute, click = setup_ui(app, tmp_path, monkeypatch, reconciliation)
    records, results, events, notices = [], [], [], []
    complete = client.complete_phs_label_print
    def record_ack(*args, **kwargs):
        records.append(dict(kwargs))
        return complete(*args, **kwargs)
    monkeypatch.setattr(client, 'complete_phs_label_print', record_ack)
    app._log_event = lambda *args, **kwargs: events.append((args, kwargs))
    app.show_status_message = lambda message, *a, **kw: notices.append(message)
    owner, method = (flow.reconciliation, 'execute') if reconciliation else (flow, 'execute_single')
    original = getattr(owner, method)
    def capture_result(*args, **kwargs):
        result = original(*args, **kwargs)
        results.append(result)
        return result
    monkeypatch.setattr(owner, method, capture_result)
    click()
    lane = app._ui_task_lane()
    pump(app, lambda: not app._phs_label_exchange_pending and not lane.is_busy())
    assert any(f'기본 프린터가 라벨 프린터가 아닙니다({private_name}). 관리자에게 알리세요.' in text for text in notices)
    assert not any(call[0] == 'StartDocW' for call in calls)
    result = results[0]
    assert not result.success and result.error_code == 'LOCAL_PRINTER_ERROR'
    assert private_name not in result.message and private_name not in repr(result)
    assert records and all(record['succeeded'] is False for record in records)
    assert private_name not in json.dumps(records, ensure_ascii=False)
    assert private_name not in json.dumps(events, ensure_ascii=False)
    assert private_name not in json.dumps(result.journal_state, ensure_ascii=False)
    assert all(private_name not in path.read_text(encoding='utf-8') for path in flow.journal.path.parent.glob('*.json'))

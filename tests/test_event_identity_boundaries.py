"""Explicit event identity boundaries; adding a caller requires classification."""
import ast
import copy
from collections import Counter
from functools import lru_cache
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {'stage', '_prepare_event_log_entry', '_checkpoint_audit_event', '_checkpoint_stored_audit_event',
    '_log_event', '_log_stored_event', '_project_stored_audit_event', '_write_event_log_entry',
    '_worker_record_context', 'record_identity', '_audit_event_contract', '_activation_event_contract',
    '_completion_event_contract', '_cancel_event_attempt', '_scanonly_completion_context'}

class IdentitySites(ast.NodeVisitor):
    def __init__(self, path):
        self.path, self.scope, self.sites, self.counts = path, [], {}, Counter()
    def visit_FunctionDef(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
    def visit_Call(self, node):
        name = (node.func.attr if isinstance(node.func, ast.Attribute)
                else node.func.id if isinstance(node.func, ast.Name) else '')
        if name in TARGETS:
            event = str(node.args[0].value) if node.args and isinstance(node.args[0], ast.Constant) else '<dynamic>'
            base = (self.path, '.'.join(self.scope), name, event)
            self.counts[base] += 1
            self.sites[(*base, self.counts[base])] = node
        self.generic_visit(node)

EVENT_SITES = {
    ('Container_Audit.py', '_audit_recovered_atomic_temps', '_log_event', 'PHS2_ATOMIC_TEMP_QUARANTINED', 1): 'new',
    ('Container_Audit.py', '_quarantine_preflight_hold_steps', '_log_event', 'PHS2_PREFLIGHT_HOLD_QUARANTINED', 1): 'new',
    ('Container_Audit.py', '_restore_quarantined_preflight_hold_steps', '_log_event', 'PHS2_PREFLIGHT_HOLD_RESTORED', 1): 'new',
    ('Container_Audit.py', '_selected_worker_identity', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_worker_record_context', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_owns_worker_record', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', 'change_worker', '_log_event', 'WORK_PAUSE', 1): 'new',
    ('Container_Audit.py', '_checkpoint_audit_event', '_worker_record_context', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_checkpoint_audit_event', '_prepare_event_log_entry', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_checkpoint_stored_audit_event', '_checkpoint_audit_event', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_project_stored_audit_event', '_write_event_log_entry', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_stage_checkpoint_audit_events', 'stage', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_activation_event_contract', '_worker_record_context', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_project_activation_event_contract', '_log_stored_event', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_audit_event_contract', '_worker_record_context', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_project_audit_event_contract', '_log_stored_event', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_build_parked_restore_contract', '_audit_event_contract', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_build_parked_restore_contract', '_audit_event_contract', '<dynamic>', 2): 'new',
    ('Container_Audit.py', '_build_parked_restore_contract', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_begin_or_resume_work_session', '_log_event', 'WORK_START', 1): 'new',
    ('Container_Audit.py', '_begin_or_resume_work_session', '_audit_event_contract', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_end_work_session', '_log_event', 'WORK_END', 1): 'new',
    ('Container_Audit.py', '_end_work_session', '_audit_event_contract', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_end_work_session', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_load_current_tray_state', '_log_event', 'TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION_RESTORE', 1): 'new',
    ('Container_Audit.py', '_load_current_tray_state', '_log_event', 'TRAY_STATE_DISCARDED_AFTER_COMPLETION', 1): 'new',
    ('Container_Audit.py', '_load_current_tray_state', '_log_event', 'TRAY_RESTORE', 1): 'new',
    ('Container_Audit.py', '_load_current_tray_state', '_log_event', 'TRAY_TAKEOVER', 1): 'new',
    ('Container_Audit.py', '_preserve_paired_stale_current', '_log_event', 'PHS2_PAIRED_STALE_CURRENT_PRESERVATION_REQUESTED', 1): 'new',
    ('Container_Audit.py', '_continue_after_paired_stale_current', '_log_event', 'PHS2_PAIRED_STALE_CURRENT_DEFERRED', 1): 'new',
    ('Container_Audit.py', '_log_current_tray_discarded', '_log_event', 'TRAY_DISCARDED_BY_OPERATOR', 1): 'new',
    ('Container_Audit.py', '_log_saved_tray_discarded', '_log_event', 'TRAY_DISCARDED_BY_OPERATOR', 1): 'new',
    ('Container_Audit.py', '_intercept_phs_reconciliation_scan.finish', '_log_event', 'PHS_RECONCILIATION_ACTION_RESOLVED', 1): 'new',
    ('Container_Audit.py', '_execute_selected_phs_label_exchange.finish', '_log_event', 'PHS_LABEL_DATE_EXCHANGED', 1): 'new',
    ('Container_Audit.py', '_execute_phs_reconciliation_exchange.finish', '_log_event', 'PHS_RECONCILIATION_LABEL_EXCHANGED', 1): 'new',
    ('Container_Audit.py', '_admin_pin_audit', '_log_event', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_admin_pin_detach_unverified', '_log_event', 'PHS2_AUDIT_EVIDENCE_UNVERIFIED_HOLD', 1): 'new',
    ('Container_Audit.py', '_admin_pin_resume_intermediate', '_log_event', 'PHS2_PREFLIGHT_HOLD_QUARANTINED', 1): 'new',
    ('Container_Audit.py', '_admin_pin_resume_intermediate', '_log_event', 'PHS2_PAIRED_STALE_CURRENT_DEFERRED', 1): 'new',
    ('Container_Audit.py', '_defer_paired_preflight_from_operations', '_log_event', 'PHS2_PAIRED_PREFLIGHT_DEFERRED', 1): 'new',
    ('Container_Audit.py', '_show_paired_preflight_handoffs', '_log_event', 'PHS2_PAIRED_RECOVERY_DEFERRED', 1): 'new',
    ('Container_Audit.py', '_identify_unreadable_audit.finish', '_log_event', 'PHS2_AUDIT_EVIDENCE_BOUND', 1): 'new',
    ('Container_Audit.py', '_recheck_stale_hold_entry.finish', '_log_event', 'PHS2_STALE_HOLD_RECHECKED', 1): 'new',
    ('Container_Audit.py', '_identify_unreadable_pair.finish', '_log_event', 'PHS2_PAIRED_MANUAL_HOLD', 1): 'new',
    ('Container_Audit.py', '_recheck_paired_preflight_receipt', '_log_event', 'PHS2_PAIRED_RECEIPT_RECHECK_REQUESTED', 1): 'new',
    ('Container_Audit.py', '_activate_master_label_tray', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_activate_master_label_tray', '_activation_event_contract', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_poll_compact_phs2_preflight', '_log_event', 'MASTER_LABEL_PREFLIGHT_FAILED', 1): 'new',
    ('Container_Audit.py', '_start_transition_tray_after_preflight_failure', '_log_event', 'MASTER_LABEL_PREFLIGHT_FAILED', 1): 'new',
    ('Container_Audit.py', '_durably_reject_preflight_hold_head', '_checkpoint_audit_event', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_durably_reject_preflight_hold_head', '_project_stored_audit_event', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_persist_existing_held_scan_audit', '_project_stored_audit_event', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_persist_existing_held_scan_audit', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_persist_existing_held_scan_audit', '_write_event_log_entry', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_persist_existing_held_scan_audit', '_log_stored_event', 'SCAN_OK', 1): 'existing',
    ('Container_Audit.py', '_queue_offline_preflight_hold.move', '_log_event', 'PHS2_PREFLIGHT_HOLD_OFFLINE_QUEUEING', 1): 'new',
    ('Container_Audit.py', '_queue_offline_preflight_hold.move', '_log_event', 'PHS2_PREFLIGHT_HOLD_QUARANTINED', 1): 'new',
    ('Container_Audit.py', '_begin_active_phs_label_refresh.finish', '_log_event', 'PHS_LABEL_ACTIVE_REFRESHED', 1): 'new',
    ('Container_Audit.py', '_intercept_active_tray_phs2_scan', '_log_event', 'ACTIVE_TRAY_PHS2_SCAN_REJECTED', 1): 'new',
    ('Container_Audit.py', '_intercept_active_tray_phs2_scan', '_log_event', 'ACTIVE_TRAY_PHS2_SCAN_INTERCEPTED', 1): 'new',
    ('Container_Audit.py', '_process_barcode_logic', '_log_event', 'SCAN_COMMAND_UNKNOWN', 1): 'new',
    ('Container_Audit.py', '_refuse_scan_during_notice', '_log_event', 'SCAN_REFUSED_DURING_NOTICE', 1): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_log_event', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_log_event', '<dynamic>', 2): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_log_event', '<dynamic>', 3): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_log_event', '<dynamic>', 4): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_log_event', '<dynamic>', 5): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_log_event', 'SCAN_FAIL_FORMAT', 1): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_checkpoint_audit_event', 'SCAN_OK', 1): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_checkpoint_audit_event', 'SCAN_OK', 2): 'new',
    ('Container_Audit.py', '_process_barcode_steps', '_project_stored_audit_event', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_process_barcode_steps', '_log_event', 'SCAN_OK', 1): 'new',
    ('Container_Audit.py', '_completion_event_contract', '_worker_record_context', '<dynamic>', 1): 'new',
    ('Container_Audit.py', 'undo_last_scan', '_cancel_event_attempt', '<dynamic>', 1): 'new',
    ('Container_Audit.py', 'undo_last_scan', '_checkpoint_stored_audit_event', 'SCAN_UNDO', 1): 'existing',
    ('Container_Audit.py', 'reset_current_work', '_cancel_event_attempt', '<dynamic>', 1): 'new',
    ('Container_Audit.py', 'reset_current_work', '_checkpoint_stored_audit_event', 'TRAY_RESET', 1): 'existing',
    ('Container_Audit.py', '_check_for_idle', '_log_event', 'IDLE_START', 1): 'new',
    ('Container_Audit.py', '_wakeup_steps', '_log_event', 'IDLE_END', 1): 'new',
    ('Container_Audit.py', '_preserve_preflight_hold_for_close', '_log_event', 'PHS2_PREFLIGHT_HOLD_CLOSE_HANDOFF', 1): 'new',
    ('Container_Audit.py', '_defer_saved_recovery_state', '_log_event', 'TRAY_PARKED', 1): 'new',
    ('Container_Audit.py', '_prepare_event_log_entry', 'record_identity', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_log_event', '_prepare_event_log_entry', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_log_event', '_worker_record_context', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_log_event', '_write_event_log_entry', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_log_stored_event', '_log_event', '<dynamic>', 1): 'bridge',
    ('Container_Audit.py', '_write_event_log_entry', 'stage', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_event_log_writer', '_worker_record_context', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_event_log_writer', '_prepare_event_log_entry', 'APP_CLOSE_DELAY', 1): 'new',
    ('Container_Audit.py', '_recover_ui_lane_fault', '_log_event', 'UI_LANE_FAULT', 1): 'new',
    ('Container_Audit.py', '_poll_app_stop_request.record', '_log_event', 'APP_STOP_DEFERRED', 1): 'new',
    ('Container_Audit.py', '_retry_precommand_operator_review_completion', '_log_event', 'TRANSFER_SEAL_PREFLIGHT_RETRY_REQUESTED', 1): 'new',
    ('Container_Audit.py', '_settle_short_completion_projection', '_log_stored_event', 'TRAY_COMPLETE', 1): 'existing',
    # M125 P4/P6: confirmed shortages release immediately; there is no undo event.
    # Keep saved-identity replay coverage at the durable held-scan resume boundary.
    ('Container_Audit.py', '_resume_operation_lease_held_scans.steps', '_project_stored_audit_event', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', '_scanonly_completion_context', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_scanonly_completion_context', '_worker_record_context', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_schedule_scanonly_transport.transport_work', '_log_stored_event', 'PRODUCT_EXCHANGE_COMPLETED', 1): 'existing',
    ('Container_Audit.py', '_prepare_and_attempt_transfer_seal_snapshot', '_log_event', 'OPERATION_LEASE_COMPLETION_TIME_RAISED', 1): 'new',
    ('Container_Audit.py', '_prepare_and_attempt_transfer_seal', '_scanonly_completion_context', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_retry_transfer_post_review.audit', '_log_event', 'TRANSFER_SEAL_REVIEW_RETRY_REQUESTED', 1): 'new',
    ('Container_Audit.py', '_log_operation_lease_release', '_log_event', 'OPERATION_LEASE_RELEASE_RESULT', 1): 'new',
    ('Container_Audit.py', '_schedule_transfer_exchange_block_receipt.finish', '_log_event', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_cancel_event_attempt', '_worker_record_context', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_log_cancel_event', '_cancel_event_attempt', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_log_cancel_event', '_log_stored_event', '<dynamic>', 1): 'existing',
    ('Container_Audit.py', 'park_current_tray', '_checkpoint_audit_event', 'TRAY_PARKED', 1): 'new',
    ('Container_Audit.py', '_show_invalid_parked_tray.finish', '_log_event', 'PHS2_DAMAGED_PARKED_DEFERRED', 1): 'new',
    ('Container_Audit.py', '_generate_test_logs', '_log_event', 'RANDOM_TEST_SESSION_START', 1): 'new',
    ('Container_Audit.py', 'initiate_master_label_replacement', '_log_event', 'HISTORICAL_REPLACE_START', 1): 'new',
    ('Container_Audit.py', '_finalize_replacement', '_log_event', 'MASTER_LABEL_REPLACEMENT_APPLIED', 1): 'new',
    ('Container_Audit.py', '_process_inline_exchange_scan', '_worker_record_context', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_process_inline_exchange_scan.steps', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_process_inline_exchange_scan.steps', '_log_stored_event', 'PRODUCT_EXCHANGE_COMPLETED', 1): 'existing',
    ('Container_Audit.py', '_apply_acked_member_exchange_ui', '_log_event', '<dynamic>', 1): 'new',
    ('Container_Audit.py', '_complete_exchange', '_log_event', 'PRODUCT_EXCHANGE_COMPLETED', 1): 'new',
    ('preflight_scan_hold.py', 'from_payload', 'record_identity', '<dynamic>', 1): 'read',
    ('tray_completion.py', 'prepared_completion_contract_steps', '_completion_event_contract', '<dynamic>', 1): 'new',
    ('tray_completion.py', 'request_complete_tray', '_scanonly_completion_context', '<dynamic>', 1): 'new',
    ('tray_completion.py', 'complete_tray_steps', '_completion_event_contract', '<dynamic>', 1): 'new',
    ('tray_completion.py', 'complete_tray_steps', '_completion_event_contract', '<dynamic>', 2): 'new',
    ('tray_completion.py', 'complete_tray_steps', '_log_event', 'TRAY_COMPLETE', 1): 'new',
    ('tray_completion.py', 'apply_completed_tray_state_steps', '_log_event', 'TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION', 1): 'new',
    ('transfer_store.py', '_linked_event_payload', 'record_identity', '<dynamic>', 1): 'read',
    ('transfer_store.py', 'preview_intent', 'record_identity', '<dynamic>', 1): 'read',
    ('transfer_store.py', 'bind_command', 'record_identity', '<dynamic>', 1): 'read',
    ('transfer_member_exchange.py', 'prepare', 'record_identity', '<dynamic>', 1): 'read',
    ('transfer_member_exchange.py', 'bind_command', 'record_identity', '<dynamic>', 1): 'read',
    ('tray_state.py', 'validate_tray_state', 'record_identity', '<dynamic>', 1): 'read',
    ('tray_state.py', 'tray_session_from_state', 'record_identity', '<dynamic>', 1): 'read',
    ('worker_roster.py', 'record_owner_matches', 'record_identity', '<dynamic>', 1): 'read',
    ('work_session_state.py', 'validate_work_session_state', 'record_identity', '<dynamic>', 1): 'read',
    ('Container_Audit.py', '_recover_automatic_offline_return_audit', '_log_event', 'PHS2_PREFLIGHT_HOLD_RESTORED', 1): 'new',
    ('Container_Audit.py', '_restore_quarantined_preflight_hold_steps.restore_automatic_return', '_log_event', 'PHS2_PREFLIGHT_HOLD_QUARANTINED', 1): 'new',
}

def identity_sites(trees=None):
    if trees is None:
        return copy.deepcopy(_cached_identity_sites())
    sites = {}
    for path in sorted(source.name for source in ROOT.glob('*.py')):
        tree = trees[path] if trees and path in trees else ast.parse((ROOT / path).read_text(encoding='utf-8-sig'))
        scan = IdentitySites(path)
        scan.visit(tree)
        sites.update(scan.sites)
    return sites

@lru_cache(maxsize=1)
def _cached_identity_sites():
    return identity_sites({})

def validate_sites(sites):
    assert sites.keys() == EVENT_SITES.keys(), 'unclassified or removed identity call site'
    for site, call in sites.items():
        if EVENT_SITES[site] != 'existing':
            continue
        if site[2] == '_write_event_log_entry':
            assert isinstance(call.args[0], ast.Dict)
            fields = {key.value: value for key, value in zip(call.args[0].keys, call.args[0].values)}
            assert 'worker_record' in fields
        else:
            assert any(kw.arg == ('worker_record' if site[2] == 'stage' else 'stored_worker_record') for kw in call.keywords), site
        assert not any(isinstance(node, ast.Attribute) and node.attr == '_worker_record_context'
                       for node in ast.walk(call)), site

def test_every_identity_call_is_classified_and_replays_pass_saved_identity():
    validate_sites(identity_sites())

def test_existing_identity_arguments_are_required_and_formatter_has_no_fallback():
    tree = ast.parse((ROOT / 'Container_Audit.py').read_text(encoding='utf-8-sig'))
    methods = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    for name in ('_log_stored_event', '_checkpoint_stored_audit_event', '_project_stored_audit_event',
                 '_prepare_event_log_entry'):
        method = methods[name]
        parameter = 'worker_record' if name == '_prepare_event_log_entry' else 'stored_worker_record'
        index = [arg.arg for arg in method.args.kwonlyargs].index(parameter)
        assert method.args.kw_defaults[index] is None
        assert not any(isinstance(node, ast.Attribute) and node.attr == '_worker_record_context'
                       for node in ast.walk(method))

EXISTING_SITES = [site for site, kind in EVENT_SITES.items() if kind == 'existing']

@pytest.mark.parametrize('site', EXISTING_SITES)
def test_guard_rejects_removed_saved_identity_at_each_replay_site(site):
    sites = identity_sites()
    call = sites[site]
    if site[2] == '_write_event_log_entry':
        index = next(i for i, key in enumerate(call.args[0].keys) if key.value == 'worker_record')
        call.args[0].keys.pop(index)
        call.args[0].values.pop(index)
    else:
        call.keywords = [kw for kw in call.keywords if kw.arg != ('worker_record' if site[2] == 'stage' else 'stored_worker_record')]
    with pytest.raises(AssertionError):
        validate_sites(sites)

def test_guard_rejects_a_new_unclassified_event_call():
    tree = ast.parse((ROOT / 'Container_Audit.py').read_text(encoding='utf-8-sig'))
    method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == '_persist_existing_held_scan_audit')
    method.body.append(ast.parse("self._log_event('NEW_UNCLASSIFIED_EVENT')").body[0])
    with pytest.raises(AssertionError, match='unclassified'):
        validate_sites(identity_sites({'Container_Audit.py': tree}))


@pytest.mark.parametrize('site', EXISTING_SITES)
@pytest.mark.parametrize('enabled', [False, True, None], ids=['off', 'on', 'legacy'])
def test_each_saved_identity_operand_survives_signal_flip(site, enabled, flow, windows, tmp_path, monkeypatch):
    """Execute each inventoried operand and its real projection boundary."""
    import csv
    import json
    from types import SimpleNamespace
    from tests.test_worker_record_identity import _app, IDENTITY

    app = _app(flow, tmp_path, enabled=enabled is True)
    event = app._checkpoint_audit_event('IDENTITY_REPLAY',
        idempotency_key='identity-boundary:' + repr(site), detail={'source': site[1]})
    record = dict(event['worker_record'])
    contract = {'worker_record': record}
    if enabled is None:
        event.pop('worker_record')
        contract = {}
    bindings = {name: contract for name in ('contract', 'undo_attempt', 'reset_attempt', 'context', 'attempt')}
    bindings.update(event=event, held_audit=event, item={'audit_event': event}, head=SimpleNamespace(audit_event=event),
                    row={'intent_id': 'identity-site'}, payload={'worker_record': record if enabled is not None else {}},
                    coordinator=SimpleNamespace(store=SimpleNamespace(scan_exchange_context=lambda _: contract)))
    call = identity_sites()[site]
    operand = next((kw.value for kw in call.keywords if kw.arg == ('worker_record' if site[2] == 'stage' else 'stored_worker_record')), None)
    stored = eval(compile(ast.Expression(operand), '<saved identity operand>', 'eval'), {'json': json}, bindings) if operand else {}
    app._worker_record_identity_enabled = not enabled
    monkeypatch.setattr(app, '_worker_record_context', lambda: pytest.fail('replay consulted live identity'))
    path = app._completion_projection_log_path(event['log_file_name'])
    if site[2] in {'stage', '_project_stored_audit_event', '_write_event_log_entry'}:
        project = lambda: app._project_stored_audit_event(event, stored_worker_record=stored)
    elif site[2] == '_checkpoint_stored_audit_event':
        def project():
            checkpoint = app._checkpoint_stored_audit_event('IDENTITY_REPLAY', stored_worker_record=stored,
                idempotency_key='identity-boundary:' + repr(site), detail={'source': site[1]},
                event_timestamp=event['log_entry']['timestamp'])
            return app._project_stored_audit_event(checkpoint, stored_worker_record=stored)
    else:
        project = lambda: app._log_stored_event('IDENTITY_REPLAY', stored_worker_record=stored,
            idempotency_key='identity-boundary:' + repr(site), detail={'source': site[1]},
            synchronous=True, event_timestamp=event['log_entry']['timestamp'])
    assert project()
    app.log_queue.join()
    original = path.read_bytes()
    app._worker_record_identity_enabled = enabled
    assert project()
    assert path.read_bytes() == original
    with path.open(encoding='utf-8-sig', newline='') as stream:
        rows = [row for row in csv.DictReader(stream) if row['event'] == 'IDENTITY_REPLAY']
    assert len(rows) == 1
    detail = json.loads(rows[0]['details'])
    expected = IDENTITY if enabled and (stored or site[2] in {'stage', '_project_stored_audit_event', '_write_event_log_entry'}) else {}
    assert {name: detail[name] for name in IDENTITY if name in detail} == expected
    assert not list(app._event_log_outbox(str(path)).directory.glob('*.json'))
    assert windows == []

from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock
pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'owned_tk_workers')


def test_legacy_completion_contract_retry_does_not_invent_identity(flow, windows, tmp_path, monkeypatch):
    from tests.test_worker_record_identity import _app, ITEM, COMPACT_QR
    from tests.test_scanonly_review_regressions import public_scan
    app = _app(flow, tmp_path, enabled=False)
    original = app._completion_event_contract
    captures = []
    def capture(**kwargs):
        result = original(**kwargs)
        captures.append((kwargs, result))
        return result
    monkeypatch.setattr(app, '_completion_event_contract', capture)
    public_scan(app, ITEM + '-SERIAL-001')
    public_scan(app, COMPACT_QR + '|QT=3')
    # M125 P2/P3: the first repeat asks; the second repeat confirms submission.
    public_scan(app, COMPACT_QR + '|QT=3')
    assert captures
    kwargs, contract = captures[-1]
    legacy = {key: value for key, value in contract.items() if key != 'worker_record'}
    monkeypatch.setattr(app, '_active_completion_event_contract', lambda: legacy)
    monkeypatch.setattr(app, '_worker_record_context', lambda: pytest.fail('legacy retry consulted live identity'))
    app._worker_record_identity_enabled = True
    assert original(**kwargs)['worker_record'] == {}
    assert windows == []

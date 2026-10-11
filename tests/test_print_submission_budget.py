"""No native printing: printer eligibility, uncertain submission and late evidence."""
import ctypes
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import threading
import time

import pytest

import phs_label_workflow as module
import Container_Audit as application
from tests.test_phs_label_workflow import FakeCentral, _tray, _target_candidate
from tests.test_phs_reconciliation_workflow import FakeReconciliationServer, _resolution, _coordinator as reconcile
from tests.test_scan_persistence_lane import ITEM, app, pump
from tk_serial_ui_lane import LaneTask
from writer_session_fence import WriterFencedError, _WRITER_LOCAL, writer_admission


class Renderer:
    def __init__(self, root):
        self.path = root / 'label.png'
        self.path.write_bytes(b'fixture-png')
    def render(self, tray, target):
        return module.RenderedPHSLabel(str(self.path), hashlib.sha256(self.path.read_bytes()).hexdigest())


def hardware(monkeypatch, *, name='Thermal label', port='USB001', driver='Thermal driver', paper_rejected=False, release=None, late_error=False):
    calls, entered = [], threading.Event()
    def unheld():
        assert int(getattr(_WRITER_LOCAL, 'depth', 0)) == 0
    class Gdi:
        def __init__(self, printer_name):
            unheld()
            calls.append(('printer', printer_name))
        def validate_paper(self, paper):
            unheld()
            calls.append(('paper', paper))
            if paper_rejected:
                raise module.PrinterError('synthetic paper rejection')
            return {}
        def print_png(self, path, spec):
            unheld()
            calls.append(('StartDocW', spec))
            entered.set()
            if release is not None:
                assert release.wait(10)
            if late_error:
                raise module.PrinterError('synthetic late submission failure')
            return SimpleNamespace(job_id=73)
    monkeypatch.setattr(module, 'GdiPrinter', Gdi)
    monkeypatch.setattr(module.WindowsGDIPhysicalLabelPrinter, '_default_printer_name', staticmethod(lambda: name))
    monkeypatch.setattr(module.WindowsGDIPhysicalLabelPrinter, '_printer_profile', staticmethod(lambda value: (port, driver)))
    return calls, entered


def coordinator(root, client, printer):
    return module.PHSLabelExchangeCoordinator(module.PHSLabelExchangeJournal(root / 'recovery.json'),
                                               client, renderer=Renderer(root), printer=printer)


def wait_for(predicate):
    deadline = time.monotonic() + 3
    while not predicate():
        assert time.monotonic() < deadline
        threading.Event().wait(0.005)


@pytest.mark.parametrize('name,port,driver', [
    ('Microsoft Print to PDF', 'USB001', 'Thermal driver'),
    ('라벨', 'PORTPROMPT:', 'Thermal driver'),
    ('라벨', 'FILE:', 'Thermal driver'),
    ('라벨', 'XPSPort:', 'Thermal driver'),
    ('라벨', 'nul:', 'Thermal driver'),
    ('OneNote (Desktop)', 'USB001', 'Thermal driver'),
    ('Fax', 'USB001', 'Thermal driver'),
    ('라벨', 'USB001', 'Microsoft Print To PDF'),
    ('라벨', 'USB001', 'Microsoft XPS Document Writer v4'),
    ('Adobe PDF', 'USB001', 'Thermal driver'),
    ('라벨', 'USB001,FILE:', 'Thermal driver'),
])
def test_virtual_printer_is_pending_before_startdoc_and_preserves_work(tmp_path, monkeypatch, name, port, driver):
    calls, _ = hardware(monkeypatch, name=name, port=port, driver=driver)
    client, tray = FakeCentral(), _tray()
    before = (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
    flow = coordinator(tmp_path, client, module.WindowsGDIPhysicalLabelPrinter())
    result = flow.execute_single(tray, _target_candidate())
    assert not result.success and result.status == 'PRINT_FAILED'
    assert f'기본 프린터가 라벨 프린터가 아닙니다({name}). 관리자에게 알리세요.' in result.message
    assert '인쇄 대기' in result.message
    assert calls == [] and client.complete_calls[-1]['succeeded'] is False
    assert client.activate_calls == []
    assert before == (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)


@pytest.mark.parametrize('custom', [False, True])
def test_paper_rejection_is_pending_before_startdoc(tmp_path, monkeypatch, custom):
    calls, _ = hardware(monkeypatch, paper_rejected=True)
    if custom:
        monkeypatch.setattr(module.WindowsGDIPhysicalLabelPrinter, '_PAPER', module.PaperSpec(paper_size_code=None, width_mm=105, height_mm=148.5))
    client, tray = FakeCentral(), _tray()
    result = coordinator(tmp_path, client, module.WindowsGDIPhysicalLabelPrinter()).execute_single(tray, _target_candidate())
    assert not result.success and result.status == 'PRINT_FAILED'
    assert '기본 프린터가 라벨 프린터가 아닙니다(Thermal label).' in result.message
    assert not any(c[0] == 'StartDocW' for c in calls)
    assert client.complete_calls[-1]['succeeded'] is False and client.activate_calls == []


@pytest.mark.parametrize('driver', ['Thermal driver', 'Physical XPS driver', 'Physical PDF capable driver'])
def test_real_printer_preserves_normal_activation_and_job_geometry(tmp_path, monkeypatch, driver):
    calls, _ = hardware(monkeypatch, driver=driver)
    client, tray = FakeCentral(), _tray()
    before = (tuple(tray.scanned_barcodes), tray.tray_size)
    result = coordinator(tmp_path, client, module.WindowsGDIPhysicalLabelPrinter()).execute_single(tray, _target_candidate())
    assert result.success and result.status == 'COMMITTED'
    spec = next(c[1] for c in calls if c[0] == 'StartDocW')
    assert spec.paper.paper_size_code == 9 and spec.output_path is None
    assert client.complete_calls[-1]['succeeded'] is True and len(client.activate_calls) == 1
    assert before == (tuple(tray.scanned_barcodes), tray.tray_size)
    assert not list(tmp_path.glob('recovery.json.print-*.json'))


@pytest.mark.parametrize('late_error', [False, True])
def test_timeout_keeps_unknown_allows_next_scan_and_close_does_not_join_auxiliary(app, tmp_path, monkeypatch, late_error):
    release = threading.Event()
    calls, entered = hardware(monkeypatch, release=release, late_error=late_error)
    monkeypatch.setattr(module, 'PRINT_SUBMIT_TIMEOUT_SECONDS', 0.02)
    client, printer = FakeCentral(), module.WindowsGDIPhysicalLabelPrinter()
    flow = coordinator(tmp_path, client, printer)
    tray, results = _tray(), []
    before = (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
    app._end_work_session = lambda **k: True
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: None
    lane = app._ui_task_lane()
    try:
        assert lane.submit(LaneTask('physical-print', app._scan_callback_epoch,
            lambda: flow.execute_single(tray, _target_candidate()), results.append,
            lambda exc: pytest.fail(type(exc).__name__)))
        pump(app, lambda: bool(results) and not lane.is_busy())
        assert entered.is_set()
        result = results[0]
        assert not result.success and result.error_code == 'PHS_LOCAL_PRINT_UNKNOWN'
        assert result.journal_state['print_result'] == 'UNKNOWN'
        assert flow.journal.load()['status'] == 'LOCAL_PRINT_STARTING'
        assert flow.journal.load()['print_result'] == 'UNKNOWN'
        assert client.complete_calls == [] and client.activate_calls == []
        assert before == (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
        aux = [t for t in threading.enumerate() if t.name == 'phs-print-submit' and t.is_alive()]
        assert len(aux) == 1
        app._process_barcode_logic(ITEM + '-next')
        pump(app, lambda: len(app.current_tray.scanned_barcodes) == 1 and not lane.is_busy())
        assert app.current_tray.scanned_barcodes == [ITEM + '-next']
        start = time.monotonic()
        app.on_closing(_confirmed=True)
        pump(app, lambda: app.root.destroyed)
        assert time.monotonic() - start < 1 and aux[0].is_alive()
        assert not lane.worker_thread.is_alive() and not app.log_thread.is_alive()
        app._cleanup_after_mainloop()
        assert app._loop_cleanup_finished and time.monotonic() - start < 1 and aux[0].is_alive()
        release.set()
        wait_for(lambda: not aux[0].is_alive())
        records = list(tmp_path.glob('recovery.json.print-*.json'))
        assert len(records) == 1 and len(printer.late_results) == 1
        late = module.PHSLabelExchangeJournal(records[0]).load()
        assert late['status'] == 'LATE_PRINT_RESULT'
        assert late['print_result']['result'] == ('ERROR' if late_error else 'SUBMITTED')
        assert flow.journal.load()['print_result'] == 'UNKNOWN'
        assert flow.journal.load()['status'] == 'LOCAL_PRINT_STARTING'
        assert client.complete_calls == [] and client.activate_calls == []
        assert sum(c[0] == 'StartDocW' for c in calls) == 1
    finally:
        release.set()
        wait_for(lambda: not any(t.name == 'phs-print-submit' and t.is_alive() for t in threading.enumerate()))


def test_deadline_boundary_completion_is_recorded_and_never_applied(tmp_path, monkeypatch):
    hardware(monkeypatch)
    monkeypatch.setattr(module, 'PRINT_SUBMIT_TIMEOUT_SECONDS', 0.02)
    original_wait = threading.Event.wait
    def expired(event, timeout=None):
        if timeout == 0.02:
            assert original_wait(event, 1)
            return False
        return original_wait(event, timeout)
    monkeypatch.setattr(threading.Event, 'wait', expired)
    client, printer = FakeCentral(), module.WindowsGDIPhysicalLabelPrinter()
    flow = coordinator(tmp_path, client, printer)
    result = flow.execute_single(_tray(), _target_candidate())
    assert result.error_code == 'PHS_LOCAL_PRINT_UNKNOWN'
    wait_for(lambda: len(list(tmp_path.glob('recovery.json.print-*.json'))) == 1)
    wait_for(lambda: not any(t.name == 'phs-print-submit' and t.is_alive() for t in threading.enumerate()))
    assert printer.late_results[0]['result'] == 'SUBMITTED'
    assert flow.journal.load()['print_result'] == 'UNKNOWN'
    assert not client.complete_calls and not client.activate_calls


def test_print_refuses_a_caller_holding_writer_admission(tmp_path, monkeypatch):
    calls, _ = hardware(monkeypatch)
    image = tmp_path / 'label.png'
    image.write_bytes(b'fixture')
    with writer_admission('phs_label_workflow'):
        with pytest.raises(WriterFencedError) as error:
            module.WindowsGDIPhysicalLabelPrinter().print_png(image, document_name='fixture')
    assert error.value.code == 'PRINT_WRITER_ADMISSION_HELD' and calls == []


def test_reconciliation_timeout_preserves_the_target_and_never_failure_acks(tmp_path, monkeypatch):
    release = threading.Event()
    hardware(monkeypatch, release=release)
    monkeypatch.setattr(module, 'PRINT_SUBMIT_TIMEOUT_SECONDS', 0.02)
    server = FakeReconciliationServer(_resolution('SPLIT'))
    printer = module.WindowsGDIPhysicalLabelPrinter()
    flow = reconcile(tmp_path, server, printer=printer)
    context = flow.reconciliation.resolve(server.resolution['scan']['active_qr_payload'])
    try:
        result = flow.reconciliation.execute(context)
        assert not result.success and result.error_code == 'PHS_LOCAL_PRINT_UNKNOWN'
        assert result.journal_state['targets'] == flow.journal.load()['targets']
        state = flow.journal.load()
        starting = [value for value in state['targets'].values() if value.get('status') == 'LOCAL_PRINT_STARTING']
        assert len(starting) == 1 and starting[0]['print_result'] == 'UNKNOWN'
        assert server.activation_writes == 0 and sum(server.print_complete_writes.values()) == 0
        assert not any(value.get('status') == 'PRINT_FAILED' for value in state['targets'].values())
    finally:
        release.set()
        wait_for(lambda: not any(t.name == 'phs-print-submit' and t.is_alive() for t in threading.enumerate()))


@pytest.mark.parametrize('reconciliation', [False, True])
@pytest.mark.parametrize('upstream_error', [False, True])
def test_actual_ui_displays_current_default_printer_and_releases_the_item(app, tmp_path, monkeypatch, reconciliation, upstream_error):
    calls, _ = hardware(monkeypatch, name='Microsoft Print to PDF', port='PORTPROMPT:')
    notices = []
    tray = _tray()
    before = (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
    app.current_tray = tray
    app.show_status_message = lambda message, *a, **kw: notices.append(message)
    app._reject_mutation_during_preflight_hold = lambda: False
    app._phs_label_exchange_pending = False
    app._phs_label_refresh_pending = False
    app.phs_label_reprint_confirm_var = SimpleNamespace(get=lambda: False)
    failed = SimpleNamespace(success=False, error_code='PHS_UPSTREAM_UNAVAILABLE',
                             message='upstream detail', journal_state={})
    if reconciliation:
        server = FakeReconciliationServer(_resolution('SPLIT'))
        flow = reconcile(tmp_path, server, printer=module.WindowsGDIPhysicalLabelPrinter())
        app.phs_label_exchange_coordinator = flow
        app._phs_reconciliation_context = flow.reconciliation.resolve(server.resolution['scan']['active_qr_payload'])
        if upstream_error:
            monkeypatch.setattr(flow.reconciliation, 'execute', lambda *a, **kw: failed)
        app._execute_phs_reconciliation_exchange()
    else:
        flow = coordinator(tmp_path, FakeCentral(), module.WindowsGDIPhysicalLabelPrinter())
        app.phs_label_exchange_coordinator = flow
        app._phs_label_exchange_available_for_tray = lambda: True
        app._selected_phs_label_candidate = _target_candidate
        if upstream_error:
            monkeypatch.setattr(flow, 'execute_single', lambda *a, **kw: failed)
        app._execute_selected_phs_label_exchange()
    lane = app._ui_task_lane()
    pump(app, lambda: not app._phs_label_exchange_pending and not lane.is_busy())
    if upstream_error:
        assert not any('upstream detail' in text or '인쇄 대기' in text for text in notices)
        assert any('F8로 복구하거나 관리자에게 문의하세요.' in text for text in notices)
    else:
        assert any('기본 프린터가 라벨 프린터가 아닙니다(Microsoft Print to PDF). 관리자에게 알리세요.' in text for text in notices)
        assert any('인쇄 대기' in text for text in notices)
    assert calls == []
    assert before == (tray.master_label_code, tuple(tray.scanned_barcodes), tray.tray_size)
    assert app.current_tray is tray


def test_denied_late_record_retains_receipt_without_changing_unknown(tmp_path, monkeypatch):
    release = threading.Event()
    hardware(monkeypatch, release=release)
    monkeypatch.setattr(module, 'PRINT_SUBMIT_TIMEOUT_SECONDS', 0.02)
    save = module.PHSLabelExchangeJournal.save
    denied = []
    def guarded_save(journal, state):
        if state.get('status') == 'LATE_PRINT_RESULT':
            denied.append(journal.path)
            raise WriterFencedError('TEST_LATE_WRITER_DENIED', 'late diagnostic denied')
        return save(journal, state)
    monkeypatch.setattr(module.PHSLabelExchangeJournal, 'save', guarded_save)
    client, printer = FakeCentral(), module.WindowsGDIPhysicalLabelPrinter()
    flow = coordinator(tmp_path, client, printer)
    try:
        result = flow.execute_single(_tray(), _target_candidate())
        assert result.error_code == 'PHS_LOCAL_PRINT_UNKNOWN'
        before = flow.journal.path.read_bytes()
        release.set()
        wait_for(lambda: not any(t in module.PRINT_SUBMISSION_THREADS and t.is_alive() for t in threading.enumerate()))
        assert len(denied) == 1 and len(printer.late_results) == 1
        assert printer.late_results[0]['result'] == 'SUBMITTED'
        assert not list(tmp_path.glob('*.print-*.json'))
        assert flow.journal.path.read_bytes() == before
        assert client.complete_calls == [] and client.activate_calls == []
    finally:
        release.set()
        wait_for(lambda: not any(t in module.PRINT_SUBMISSION_THREADS and t.is_alive() for t in threading.enumerate()))


def test_getprinter_profile_reads_port_and_driver_and_closes_handle(monkeypatch):
    strings = [ctypes.create_unicode_buffer(value) for value in ('PORTPROMPT:', 'Microsoft Print to PDF')]
    calls = []
    def opened(name, handle, defaults):
        handle._obj.value = 1
        return True
    def queried(handle, level, buffer, size, needed):
        assert level == 2
        needed._obj.value = ctypes.sizeof(module._PrinterInfo2W)
        calls.append(buffer is not None)
        if buffer is None:
            return False
        info = ctypes.cast(buffer, ctypes.POINTER(module._PrinterInfo2W)).contents
        info.pPortName, info.pDriverName = (ctypes.addressof(value) for value in strings)
        return True
    def closed(handle):
        calls.append('closed')
        return True
    monkeypatch.setattr(module.ctypes, 'WinDLL', lambda *a, **k: SimpleNamespace(OpenPrinterW=opened, GetPrinterW=queried, ClosePrinter=closed))
    assert module.WindowsGDIPhysicalLabelPrinter._printer_profile('printer') == ('PORTPROMPT:', 'Microsoft Print to PDF')
    assert calls == [False, True, 'closed']

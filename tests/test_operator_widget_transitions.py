"""Operator-visible transitions through owned, measured native Tk widgets."""
import re
import tkinter as tk
from tkinter import ttk

import pytest

from Container_Audit import ContainerAudit, TraySession
from tests.native_widgets import (
    action_buttons, assert_contained, build_center, native_tk_root, rectangle, resize_root,
)
from warning_presenter import (
    CompletionOutcome, CompletionOutcomeSnapshot, Notice, NoticeSeverity, WarningPresenter,
)

pytestmark = pytest.mark.real_gui


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


@pytest.fixture
def native_operator(native_tk_root, request):
    root = native_tk_root
    configuration = getattr(request, 'param', {})
    resize_root(root, *configuration.get('viewport', (2200, 1500)))
    app, center = build_center(root, scale=configuration.get('scale', 1.0), width=900, height=900)
    app.current_tray = TraySession()
    right = ttk.Frame(root)
    width, height = configuration.get('right_size', (420, 900))
    right.place(x=1000, y=0, width=width, height=height)
    app._create_right_sidebar_content(right)
    app.status_label = tk.Label(root, text='스캐너 준비')
    app.status_label.place(x=0, y=950, width=800, height=40)
    app._update_center_display()
    root.update()
    return app, center, right


def _tray(app, barcodes=()):
    app.current_tray = TraySession(
        master_label_code='PHS=2|CLC=AAA2270730100|QT=3', item_code='AAA2270730100',
        item_name='fixture item', scanned_barcodes=list(barcodes), tray_size=3,
    )
    app.scanned_listbox.delete(0, 'end')
    for index, barcode in enumerate(barcodes, 1):
        app.scanned_listbox.insert(0, app._format_scanned_list_row(index, barcode))
    if barcodes:
        app.warning_presenter.record_normal_scan(barcodes[-1])
    app._update_center_display()
    app.root.update()


def test_native_constructor_binds_f8_shift_f8_and_exchange_button(
    native_tk_root, monkeypatch, tmp_path
):
    import Container_Audit as module

    root = native_tk_root
    callbacks = []
    bootstrap = []
    setup_paths = ContainerAudit._setup_paths_and_dirs

    def owned_paths(app):
        app.application_path = str(tmp_path / 'owned application')
        Path(app.application_path).mkdir()
        setup_paths(app)

    from pathlib import Path
    monkeypatch.setenv('CONTAINER_AUDIT_STARTUP_GEOMETRY', '1366x768+10000+10000')
    monkeypatch.setenv('CONTAINER_AUDIT_DATA_ROOT', str(tmp_path / 'data'))
    monkeypatch.setenv('KMTECH_TEST_SILENT_AUDIO', '1')
    monkeypatch.setattr(module.tk, 'Tk', lambda: root)
    monkeypatch.setattr(module, 'container_startup_logistics_client', lambda: None)
    monkeypatch.setattr(module, 'start_direct_sync_auto_bootstrap', lambda **kwargs: bootstrap.append(kwargs))
    monkeypatch.setattr(ContainerAudit, '_setup_paths_and_dirs', owned_paths)
    monkeypatch.setattr(ContainerAudit, 'load_items', lambda self: [])
    monkeypatch.setattr(ContainerAudit, '_on_phs_label_exchange_shortcut', lambda self, event=None: callbacks.append('exchange'))
    monkeypatch.setattr(ContainerAudit, '_show_phs_label_legacy_single_fallback', lambda self, event=None: callbacks.append('legacy'))
    app = ContainerAudit.__new__(ContainerAudit)
    try:
        ContainerAudit.__init__(app)
        root.update()
        root.focus_force()
        root.event_generate('<KeyPress-F8>')
        root.update()
        root.event_generate('<Shift-KeyPress-F8>')
        root.update()
        assert callbacks == ['exchange', 'legacy']
        center = ttk.Frame(root)
        center.place(x=0, y=0, width=900, height=700)
        app._create_center_content(center)
        root.update()
        assert app.phs_label_exchange_button.cget('text') == '현품표 교체'
        # This contract checks the registered command. Operational readiness is
        # exercised by the workflow cases; startup deliberately has no client.
        app.phs_label_exchange_button.state(['!disabled'])
        app.phs_label_exchange_button.invoke()
        assert callbacks == ['exchange', 'legacy', 'exchange']
        assert len(bootstrap) == 1
        assert Path(bootstrap[0]['app_root']).is_relative_to(tmp_path)
    finally:
        if getattr(app, 'log_thread', None) is not None:
            app.log_queue.put(None)
            app.log_thread.join(timeout=5)
            assert not app.log_thread.is_alive()


def test_native_operator_has_one_scan_history_and_one_progress_count(native_operator):
    app, center, right = native_operator
    barcode = 'AAA2270730100|SERIAL=SERIAL-000000123456|UNRECOGNIZED=FULL-TELEGRAM-PAYLOAD'
    _tray(app, [barcode])
    assert [w for w in _walk(center) if isinstance(w, tk.Listbox)] == [app.scanned_listbox]
    assert not [w for w in _walk(right) if isinstance(w, (tk.Listbox, ttk.Treeview, ttk.Progressbar))]
    assert app.main_count_label.cget('text') == '1 / 3'
    texts = [str(w.cget('text')) for w in _walk(right) if isinstance(w, (tk.Label, ttk.Label))]
    assert not any(re.search(r'\b\d+\s*/\s*\d+\b', text) for text in texts)
    assert '마지막 정상 스캔' in texts and '다음 행동' in texts
    shown = app.last_scan_value_label.cget('text')
    assert shown and barcode not in shown and '|' not in shown and '=' not in shown
    assert app.warning_presenter.state.last_normal_scan == barcode
    assert app.current_tray.scanned_barcodes == [barcode]
    assert app.follow_up_label.cget('text') == '다음 제품 스캔'
    for widget in [app.last_scan_value_label, app.follow_up_label, app.scanned_listbox]:
        assert_contained(widget, right if widget is not app.scanned_listbox else center)


def test_native_duplicate_ack_restores_input_and_preserves_actual_rows(native_operator):
    app, center, _right = native_operator
    barcodes = ['AAA2270730100-001', 'AAA2270730100-002']
    _tray(app, barcodes)
    before = app.scanned_listbox.get(0, 'end')
    geometry = rectangle(app.scanned_listbox)
    notice = Notice(code='scan.duplicate', title='중복 스캔', message='이미 처리된 제품입니다.',
                    severity=NoticeSeverity.ERROR, blocking=True)
    assert app.warning_presenter.present(notice) is True
    assert app.warning_presenter.present(notice) is False
    app._update_center_display()
    app.root.update()
    assert app.info_cards['status']['value'].cget('text') == '중복 확인'
    assert str(app.scan_entry.cget('state')) == 'disabled'
    assert_contained(app.notice_ack_button, center)
    assert app.scanned_listbox.get(0, 'end') == before
    app.notice_ack_button.invoke()
    app.root.update()
    assert app.warning_presenter.state.active_notice is None
    assert app.info_cards['status']['value'].cget('text') == '작업 중'
    assert app.follow_up_label.cget('text') == '다음 제품 스캔'
    assert str(app.scan_entry.cget('state')) == 'normal'
    assert app.scanned_listbox.get(0, 'end') == before
    assert rectangle(app.scanned_listbox) == geometry
    assert app.warning_presenter.state.last_normal_scan == barcodes[-1]


def test_native_operator_review_keeps_scan_stopped_through_status_refresh(native_operator):
    app, _center, _right = native_operator
    _tray(app, ['AAA2270730100-001'])
    app.warning_presenter.present_completion(CompletionOutcomeSnapshot(
        outcome=CompletionOutcome.OPERATOR_REVIEW, item_name='fixture item',
        master_label=app.current_tray.master_label_code, scan_count=1, target_count=3,
        message='서버 판정에 담당자 확인이 필요합니다.',
    ))
    app._render_warning_state()
    app.root.update()
    assert str(app.scan_entry.cget('state')) == 'disabled'
    assert app.status_label.cget('text') == '스캔 중지 · 담당자 확인'
    app.show_status_message('후속 안내', duration=0)
    app._reset_status_message()
    assert app.status_label.cget('text') == '스캔 중지 · 담당자 확인'
    app.warning_presenter = WarningPresenter()
    app._render_warning_state()
    assert str(app.scan_entry.cget('state')) == 'normal'
    assert app.status_label.cget('text') == '스캐너 준비'


def test_native_stage_copy_round_trips_from_master_to_product(native_operator):
    app, _center, _right = native_operator
    waiting = app.stage_label.cget('text')
    assert '1 / 2' in waiting and '현품표' in waiting
    _tray(app)
    assert '2 / 2' in app.stage_label.cget('text') and '제품' in app.stage_label.cget('text')
    app.current_tray = TraySession()
    app._update_center_display()
    assert app.stage_label.cget('text') == waiting


@pytest.mark.parametrize('state', ['duplicate', 'operator_review', 'acked', 'recovered'])
def test_native_scan_rows_survive_notice_completion_and_recovery(native_operator, state):
    app, center, _right = native_operator
    barcodes = ['AAA2270730100-001', 'AAA2270730100-002', 'AAA2270730100-003']
    _tray(app, barcodes)
    identity = str(app.scanned_listbox)
    if state == 'duplicate':
        app.warning_presenter.present(Notice(code='scan.duplicate', title='중복 스캔',
            message='이미 처리된 제품입니다.', severity=NoticeSeverity.ERROR, blocking=True))
    elif state in ['operator_review', 'acked']:
        app.warning_presenter.present_completion(CompletionOutcomeSnapshot(
            outcome=CompletionOutcome.OPERATOR_REVIEW if state == 'operator_review' else CompletionOutcome.ACKED,
            item_name='fixture item', master_label=app.current_tray.master_label_code,
            scan_count=3, target_count=3, message='담당자 확인' if state == 'operator_review' else '서버 확인 완료',
        ))
        if state == 'acked':
            app.current_tray = TraySession()
            app.scanned_listbox.delete(0, 'end')
            barcodes = []
    else:
        barcodes = barcodes[:2]
        _tray(app, barcodes)
        app.current_tray.is_restored_session = True
        app.warning_presenter.present(Notice(code='tray.recovered', title='작업 복구 완료',
            message='다음 제품을 스캔하세요.', severity=NoticeSeverity.SUCCESS))
    app._update_center_display()
    app.root.update()
    assert str(app.scanned_listbox) == identity
    rows = app.scanned_listbox.get(0, 'end')
    assert len(rows) == len(barcodes)
    assert all(barcode not in row for barcode in barcodes for row in rows)
    assert bool(app.notice_ack_button.winfo_ismapped()) == (state in ['duplicate', 'operator_review'])
    for button in action_buttons(app):
        assert_contained(button, center)
    assert_contained(app.scanned_listbox, center)
    if rows:
        assert any(app.scanned_listbox.bbox(index) for index in range(len(rows)))
    if state == 'recovered':
        assert '2건' in app.scanned_list_header_label.cget('text')


def test_native_action_copy_and_rows_round_trip_without_exposing_hidden_operations(native_operator):
    app, center, _right = native_operator
    observations = []
    for width in [959, 960, 580, 959]:
        center.place_configure(width=width)
        app.root.update()
        app._apply_center_layout(center, width, 900)
        app.root.update()
        buttons = action_buttons(app)
        for button in buttons:
            assert_contained(button, center)
        spans = [(button.winfo_rooty(), button.winfo_rooty() + button.winfo_height()) for button in buttons]
        if width == 580:
            assert max(y for y, _bottom in spans[:2]) < min(bottom for _y, bottom in spans[:2])
            assert max(bottom for _y, bottom in spans[:2]) <= min(y for y, _bottom in spans[2:])
            assert max(y for y, _bottom in spans[2:]) < min(bottom for _y, bottom in spans[2:])
        else:
            assert max(y for y, _bottom in spans) < min(bottom for _y, bottom in spans)
        assert app.submit_tray_button.cget('text') == ('트레이 제출' if width >= 960 else '제출')
        assert not any(w.winfo_ismapped() for w in [app.reset_button, app.replace_master_label_button, app.exchange_button])
        observations.append([rectangle(button) for button in buttons])
    assert observations[0] == observations[-1]


def test_native_rebuilt_panes_ignore_stale_configure_callbacks(native_operator, monkeypatch):
    app, center, right = native_operator
    callbacks = {center: [], right: []}
    for widget in [center, right]:
        original = widget.bind

        def record(sequence, callback=None, add=None, *, widget=widget, original=original):
            if sequence == '<Configure>' and callback is not None:
                callbacks[widget].append(callback)
            return original(sequence, callback, add)

        monkeypatch.setattr(widget, 'bind', record)
    app._create_center_content(center)
    app._create_right_sidebar_content(right)
    app.root.update()
    old = {widget: callbacks[widget][-1] for widget in [center, right]}
    old_scripts = {widget: widget.bind('<Configure>') for widget in [center, right]}
    app._create_center_content(center)
    app._create_right_sidebar_content(right)
    app.root.update()
    before = [rectangle(app.follow_up_label), rectangle(app.scanned_listbox)]
    jobs = app.root.tk.call('after', 'info')
    for widget in [center, right]:
        assert widget.bind('<Configure>') != old_scripts[widget]
        assert old[widget] is not callbacks[widget][-1]
        old[widget](None)
    assert app.root.tk.call('after', 'info') == jobs
    assert [rectangle(app.follow_up_label), rectangle(app.scanned_listbox)] == before
    center.place_configure(width=580)
    app.root.update()
    assert app.scanned_listbox.winfo_width() < before[1][2]
    for button in action_buttons(app):
        assert_contained(button, center)


def test_native_notice_rebuild_ignores_old_label_and_wraps_live_width(native_operator, monkeypatch):
    app, center, _right = native_operator
    old_label = app.notice_message_label
    old_generation = app._center_widget_generation
    old_wrap = old_label.cget('wraplength')
    app._create_center_content(center)
    app.root.update()
    current = app.notice_message_label
    live_before = current.cget('wraplength')
    app._apply_notice_message_wraplength(old_generation)
    assert current.cget('wraplength') == live_before
    assert old_label.cget('wraplength') == old_wrap
    values = []
    for width in [900, 580, 900]:
        center.place_configure(width=width)
        app.root.update()
        app._apply_notice_message_wraplength(app._center_widget_generation)
        app.root.update()
        wrap = int(float(current.cget('wraplength')))
        assert 0 < wrap <= current.winfo_width()
        assert_contained(current, center)
        values.append(wrap)
    assert values[0] == values[2] > values[1]


@pytest.mark.parametrize('native_operator', [{'scale': 1.4, 'viewport': (1366, 768), 'right_size': (302, 707)}], indirect=True)
def test_native_right_cards_and_legend_restore_after_compact_round_trip(native_operator):
    app, _center, right = native_operator
    assert app.scale_factor == 1.4
    snapshots = []
    for width, height in [(302, 707), (510, 1324), (302, 707)]:
        resize_root(app.root, 2560 if height == 1324 else 1366, 1392 if height == 1324 else 768)
        app.apply_scaling()
        right.place_configure(width=width, height=height)
        app.root.update()
        app._apply_right_sidebar_layout()
        app.root.update()
        assert bool(app._legend_frame.winfo_ismapped()) == (height == 1324)
        values = [app.info_cards[key]['value'] for key in ['status', 'direct_sync', 'stopwatch', 'avg_time', 'best_time']]
        values += [app.last_scan_value_label, app.follow_up_label]
        for widget in values:
            assert_contained(widget, right)
        if height == 707:
            snapshots.append([rectangle(widget) for widget in values])
    assert snapshots[0] == snapshots[1]


@pytest.mark.parametrize('height', [694, 826])
def test_native_left_view_survives_rebuild_and_rows_survive_resize(native_tk_root, height):
    root = native_tk_root
    resize_root(root, 2200, 1600)
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = root
    app.scale_factor = 1.4
    app.worker_name = '캡처 작업자'
    app.show_tray_image_var = tk.BooleanVar(master=root, value=False)
    app.style = ttk.Style(root)
    app.apply_scaling()
    left = ttk.Frame(root)
    left.place(x=0, y=0, width=322, height=height)
    app._create_left_sidebar_content(left)
    root.update()
    app.parked_tree.insert('', 'end', iid='owned-row', values=('보존 품목', '2'))
    assert app._update_parked_recovery_affordance() == 1
    assert app.left_context_switch_button.cget('text') == '보류 1건 보기'
    app.left_context_switch_button.invoke()
    root.update()
    assert app.parked_tree.winfo_ismapped() and not app.summary_tree.winfo_ismapped()
    assert app.left_context_switch_button.cget('text') == '현재·기록 보기'
    trees = (str(app.parked_tree), str(app.summary_tree))
    snapshots = []
    for width, pane_height in [(322, height), (559, 1500), (322, height)]:
        left.place_configure(width=width, height=pane_height)
        root.update()
        app._apply_left_sidebar_layout()
        root.update()
        assert app.parked_tree.item('owned-row', 'values') == ('보존 품목', '2')
        assert (str(app.parked_tree), str(app.summary_tree)) == trees
        for widget in [app.worker_info_label, app.change_worker_button, app.tray_image_checkbox]:
            assert_contained(widget, left)
        assert app.tray_image_checkbox.cget('text') == ('트레이 이미지 보기' if width == 559 else '트레이 이미지')
        if width == 322:
            assert_contained(app.left_context_switch_button, left)
            assert app.parked_tree.winfo_ismapped() and not app.summary_tree.winfo_ismapped()
            snapshots.append(rectangle(app.left_context_switch_button))
        else:
            assert app.parked_tree.winfo_ismapped() and app.summary_tree.winfo_ismapped()
    assert snapshots[0] == snapshots[-1]
    rebuilt = ttk.Frame(root)
    rebuilt.place(x=700, y=0, width=322, height=height)
    app._create_left_sidebar_content(rebuilt)
    root.update()
    assert app.parked_tree.winfo_ismapped() and not app.summary_tree.winfo_ismapped()
    assert app.left_context_switch_button.cget('text') == '현재·기록 보기'

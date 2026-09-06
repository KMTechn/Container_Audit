"""Owned native Tk widgets: deterministic geometry, no application or modal input."""
import tkinter as tk
from tkinter import ttk

import pytest

@pytest.fixture(scope='session')
def native_tk_interpreter():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f'native Tk display unavailable: {exc}')
    root.withdraw()
    try:
        yield root
    finally:
        root.destroy()


@pytest.fixture
def native_tk_root(native_tk_interpreter):
    root = tk.Toplevel(native_tk_interpreter)
    callback_errors = []
    old_handler = native_tk_interpreter.report_callback_exception
    native_tk_interpreter.report_callback_exception = lambda *error: callback_errors.append(error)
    root.withdraw()
    root.overrideredirect(True)
    root.attributes('-alpha', 0.0)
    root.maxsize(10000, 10000)
    root.tk.call('tk', 'scaling', 2.00098)
    ttk.Style(root).theme_use('clam')
    resize_root(root, 1366, 768)
    try:
        yield root
        assert not callback_errors, [(kind.__name__, str(value)) for kind, value, _tb in callback_errors]
    finally:
        for job in root.tk.splitlist(root.tk.call('after', 'info')):
            root.after_cancel(job)
        if root.winfo_exists():root.destroy()
        native_tk_interpreter.report_callback_exception = old_handler


def resize_root(root, width, height):
    root.geometry(f'{width}x{height}+10000+10000')
    root.deiconify()
    root.update()
    assert (root.winfo_width(), root.winfo_height()) == (width, height)


def rectangle(widget):
    return (widget.winfo_rootx(), widget.winfo_rooty(), widget.winfo_width(), widget.winfo_height())


def assert_contained(widget, parent):
    assert widget.winfo_ismapped(), str(widget)
    x, y, width, height = rectangle(widget)
    px, py, pw, ph = rectangle(parent)
    assert width > 1 and height > 1
    assert px <= x and py <= y and x + width <= px + pw and y + height <= py + ph, (
        str(widget), (x-px, y-py, width, height), (pw, ph))


def build_center(root, *, scale=1.0, width=815, height=704, barcode=''):
    from Container_Audit import ContainerAudit, TraySession
    from warning_presenter import WarningPresenter
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = root
    app.scale_factor = scale
    app.style = ttk.Style(root)
    app.apply_scaling()
    app.current_tray = TraySession(
        master_label_code='PHS=2|CLC=AAA2270730200|QT=3', item_code='AAA2270730200',
        item_name='계약 테스트 품목', scanned_barcodes=[barcode] if barcode else [], tray_size=3)
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.warning_presenter = WarningPresenter()
    app.info_cards = {}
    if barcode:app.warning_presenter.record_normal_scan(barcode)
    parent = ttk.Frame(root)
    parent.place(x=0, y=0, width=width, height=height)
    app._create_center_content(parent)
    if barcode:app.scanned_listbox.insert('end', app._format_scanned_list_row(1, barcode))
    root.update()
    app._apply_center_layout(parent, width, height)
    root.update()
    return app, parent


def action_buttons(app):
    return [app.undo_button, app.park_button, app.submit_tray_button, app.operations_button]

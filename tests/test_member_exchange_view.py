from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import threading

import pytest

import Container_Audit as ca
from tests.test_tk_serial_ui_lane import FakeTkRoot
from tests.test_transfer_seal import _compact_phs2_qr
from transfer_member_exchange import MemberExchangeAttempt, TransferMemberExchangeStore


def _widget(root, **options):
    """Fake layout calls, but model focus and Tk's toplevel Destroy binding."""
    widget = Mock()
    widget.options = options
    widget.bindings = {}
    widget.winfo_exists.return_value = True
    for name, value in (("reqheight", 100), ("reqwidth", 900),
                        ("screenwidth", 1024), ("screenheight", 768)):
        getattr(widget, f"winfo_{name}").return_value = value
    widget.cget.side_effect = lambda key: options.get(key, "")
    widget.heading.return_value = "barcode"
    widget.bind.side_effect = lambda event, callback, **kw: widget.bindings.update({event: callback})
    widget.protocol.side_effect = widget.bind.side_effect
    widget.focus.side_effect = widget.focus_set.side_effect = lambda: setattr(root, "focused", widget)
    widget.invoke.side_effect = lambda: options["command"]()

    def destroy():
        widget.winfo_exists.return_value = False
        root.focused = root.operations_button
        callback = widget.bindings.get("<Destroy>")
        if callback:
            callback(SimpleNamespace(widget=widget))

    widget.destroy.side_effect = destroy
    return widget


@pytest.fixture
def exchange_owner(monkeypatch, tmp_path):
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    app.root = root = FakeTkRoot()
    root.operations_button = object()
    root.focused = root.operations_button
    root.focus_get = lambda: root.focused
    app.scan_entry = _widget(root)
    app.style = SimpleNamespace(lookup=lambda *args: 20)
    for namespace, names in ((ca.tk, ("Toplevel", "IntVar")),
                             (ca.ttk, ("Frame", "Label", "LabelFrame", "Spinbox",
                                       "Treeview", "Scrollbar", "Entry", "Button"))):
        for name in names:
            monkeypatch.setattr(namespace, name, lambda *args, **kw: _widget(root, **kw))
    app._large_text_pane = lambda *args, **kw: _widget(root)
    app._tree_column_required_width = lambda *args, **kw: 160
    for name in ("_invalidate_pending_scan_callbacks", "_update_action_button_states",
                 "_bind_label_to_container_width", "_apply_tree_row_styles"):
        setattr(app, name, Mock())
    app._reject_mutation_during_preflight_hold = lambda: False
    app._transfer_member_exchange_blocks_local_action = lambda action: False
    app._exact_transfer_exchange_blocked = lambda: True
    app._preflight_context_blocks_mutation = lambda: False
    app._call_transfer_ui_sync = lambda callback: callback()
    app._work_transfer_coordinator_ui_snapshot = lambda **kw: {}
    app._apply_transfer_coordinator_ui_snapshot = Mock()
    app.worker_name = "focus-test"
    app.current_tray = ca.TraySession(
        master_label_code=_compact_phs2_qr(), item_code="AAA2270730100",
        item_name="focus fixture", scanned_barcodes=["AAA2270730100-OLD-1", "AAA2270730100-OLD-2"],
    )
    app.current_tray.operation_lease_id = "focus-lease"
    store = TransferMemberExchangeStore(tmp_path / "exchange.db", owner_thread_id_provider=threading.get_ident)
    app._transfer_member_exchange_runtime = Mock(return_value=SimpleNamespace(store=store))
    app._log_event = Mock(return_value=True)
    return app, store


@pytest.mark.parametrize("close_path", ["cancel_button", "window_close", "success"])
def test_exchange_close_returns_focus_to_scan_entry(exchange_owner, monkeypatch, close_path, record_property):
    app, store = exchange_owner
    app._show_exchange_dialog_after_coordinator_admission()
    dialog = app.exchange_dialog
    assert app.root.focus_get() is app.exchange_scan_entry
    assert "<Escape>" not in dialog.bindings
    # Child destruction also reaches the toplevel bindtag and must not steal focus.
    destroy_callback = dialog.bindings.get("<Destroy>")
    if destroy_callback:
        destroy_callback(SimpleNamespace(widget=app.exchange_scan_entry))
    assert not app.root.jobs
    session = app.current_exchange_session
    session.current_step = "scan_good"
    session.target_quantity = 1
    session.defective_barcodes = [app.current_tray.scanned_barcodes[0]]
    session.good_barcodes = ["AAA2270730100-NEW-1"]
    tray_before = asdict(app.current_tray)
    store_before = Path(store.db_path).read_bytes()

    if close_path == "success":
        events = []
        attempt = MemberExchangeAttempt("focus-intent", "ACKED", "PENDING")
        coordinator = SimpleNamespace(
            _owner_thread_id_provider=threading.get_ident,
            prepare=Mock(side_effect=lambda **kw: events.append("prepare") or attempt),
            attempt=Mock(side_effect=lambda intent: events.append("ACKED") or attempt),
        )
        app._transfer_member_exchange_runtime.return_value = coordinator

        def apply_acked(result):
            assert result is attempt
            events.append("apply")
            app.current_tray.scanned_barcodes[0] = session.good_barcodes[0]
            return True

        app._apply_acked_member_exchange = apply_acked
        monkeypatch.setattr(ca.messagebox, "showinfo", lambda *args, **kw: events.append("notice"))
        app.exchange_complete_button.invoke()
        assert events == ["prepare", "ACKED", "apply", "notice"]
        assert coordinator.prepare.call_args.kwargs["old_barcodes"] == tuple(session.defective_barcodes)
        assert coordinator.prepare.call_args.kwargs["new_barcodes"] == tuple(session.good_barcodes)
        coordinator.attempt.assert_called_once_with("focus-intent")
        assert app.current_tray.scanned_barcodes == ["AAA2270730100-NEW-1", "AAA2270730100-OLD-2"]
    else:
        if close_path == "cancel_button":
            app.exchange_cancel_button.invoke()
        else:
            dialog.bindings["WM_DELETE_WINDOW"]()
        assert asdict(app.current_tray) == tray_before
        assert Path(store.db_path).read_bytes() == store_before
        app._transfer_member_exchange_runtime.assert_not_called()
        app._log_event.assert_called_once()
        assert app._log_event.call_args.args == ("PRODUCT_EXCHANGE_CANCELLED",)
        assert app._log_event.call_args.kwargs["synchronous"] is True

    assert not dialog.winfo_exists()
    assert app.exchange_dialog is None
    assert app.current_exchange_session.current_step == "not_started"
    assert not app._active_transfer_exchange_mode
    assert app._active_transfer_exchange_intent_id == ""
    assert len(app.current_tray.scanned_barcodes) == 2
    while app.root.run_one():
        pass
    record_property("focus_after_close", "scan_entry" if app.root.focus_get() is app.scan_entry else "operations_button")
    record_property("tray_count", len(app.current_tray.scanned_barcodes))
    assert app.root.focus_get() is app.scan_entry
    assert app.focus_return_job is None

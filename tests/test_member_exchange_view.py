"""R7 replaces the product-exchange window with the scanner-owned flow."""
import pytest
from tests.test_legacy_label_transition import flow, _rows
from tests.test_w9scanonly_workflow import windows, _active
from tests.operation_lease_fixtures import fixed_operation_lease_clock
from tests.test_phs2_master_preflight import ITEM, _pump_until

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")

@pytest.mark.parametrize("entry", ["button", "card", "card_restart"])
def test_exchange_entry_keeps_scan_focus_and_durable_tray(flow, windows, entry):
    app = _active(flow)
    old = f"{ITEM}-SERIAL-001"
    app._process_barcode_logic(old)
    if entry == "button":
        app.show_exchange_dialog()
    else:
        app._process_barcode_logic("KMCMD:EXCHANGE")
    if entry == "card_restart":
        app._process_barcode_logic(old)
        app._process_barcode_logic("KMCMD:EXCHANGE")
    assert app._inline_exchange_mode == "old"
    assert app._inline_exchange_target == ""
    assert app.current_tray.scanned_barcodes == [old]
    assert app.current_tray.tray_size == 3
    assert not getattr(app, "exchange_dialog", None)
    assert not _rows(app, "PRODUCT_EXCHANGE_COMPLETED")
    assert windows == []

@pytest.mark.parametrize("stage", ["NG", "SEALED", "PACKAGED", "SHIPPED"])
def test_known_ineligible_replacement_does_not_change_tray(flow, windows, stage):
    app = _active(flow)
    old,new = f"{ITEM}-SERIAL-001", f"{ITEM}-SERIAL-999"
    app._process_barcode_logic(old)
    app._scanonly_known_products = {new: {"quality_result": stage, "bundle_state": stage}}
    app._process_barcode_logic("KMCMD:EXCHANGE")
    app._process_barcode_logic(old)
    app._process_barcode_logic(new)
    assert app.current_tray.scanned_barcodes == [old]
    assert app._inline_exchange_mode == "new"
    assert not _rows(app, "PRODUCT_EXCHANGE_COMPLETED")
    assert windows == []

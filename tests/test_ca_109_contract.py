"""Contract additions use original codes and durable completion quantities."""
import pytest

import ca_screen_bridge as screen
from tests.test_ca_screen_bridge import _app, _idle, _schema_errors
from tests.test_w9scanonly_workflow import flow, windows  # noqa: F401
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401

pytestmark = pytest.mark.usefixtures("windows", "fixed_operation_lease_clock")


def test_original_product_code_reaches_list_and_recent_result(flow):
    app = _app(flow)
    raw = app.current_tray.known_member_barcodes[0]
    processor = screen.CaProcessor(app)
    processor.scan(raw, {})
    _idle(app, lambda: len(app.current_tray.scanned_barcodes) == 1)
    state = processor.state()
    assert not _schema_errors(state, screen_contract())
    assert state["work"]["list"][0]["code"] == raw
    assert raw in state["work"]["result"]["sub"]


def screen_contract():
    from tests.test_ca_screen_bridge import CONTRACT
    return CONTRACT["state"]


def test_exchange_phases_include_original_codes_and_clear_for_another_tray(flow):
    app = _app(flow)
    label = app.current_tray.master_label_code
    app._inline_exchange_mode = "old"
    state = screen.present_ca(app)
    assert state["work"]["exchange"] == {"phase": "remove", "remove": {"code": None}, "insert": {"code": None}}
    app._inline_exchange_mode = "new"
    app._inline_exchange_target = "original-removed-product-code"
    assert screen.present_ca(app)["work"]["exchange"]["remove"]["code"] == app._inline_exchange_target
    app._inline_exchange_mode = ""
    app._last_inline_exchange = {"master_label": label, "remove": "original-removed-product-code", "insert": "original-inserted-product-code"}
    state = screen.present_ca(app)
    assert state["work"]["exchange"]["phase"] == "done"
    assert not _schema_errors(state, screen_contract())
    app.current_tray.master_label_code = "another-master-label"
    assert "exchange" not in screen.present_ca(app)["work"]


def test_today_products_survive_completed_history_reload(flow):
    app = _app(flow)
    app._load_session_state()
    members = list(app.current_tray.known_member_barcodes)
    processor = screen.CaProcessor(app)
    for index, member in enumerate(members, 1):
        processor.scan(member, {})
        _idle(app, lambda: len(app.current_tray.scanned_barcodes) >= index
              or not app.current_tray.master_label_code)
    if app.current_tray.master_label_code:
        app.request_complete_tray()
    _idle(app, lambda: not app.current_tray.master_label_code)
    before = screen.today_values(app)
    assert sum(row["products"] for row in before["rows"]) == len(members)
    app._load_session_state()
    after = screen.today_values(app)
    assert after["rows"] == before["rows"]


def test_admin_menu_pin_flags_match_the_active_gate(flow):
    app = _app(flow)
    state = screen.present_ca(app)
    assert all(type(row["pin"]) is bool and row["pin"] == (row["name"] in screen.ADMIN_PIN)
               for row in state["admin_menu"])

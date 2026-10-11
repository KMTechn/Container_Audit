"""Worker guidance for completed trays without a central seal receipt."""
import datetime
from types import SimpleNamespace

import pytest
import session_history

from Container_Audit import ContainerAudit
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401
from tests.test_legacy_label_transition import (
    flow, _details, _phs2_tray, _rows, _scan_products,
)
from tests.test_phs2_master_preflight import (
    BlockingClient, COMPACT_QR, ITEM, _pump_until, _resolved,
)
from transfer_seal import SealAttempt


GUIDANCE = "출고 전 관리자 보충 필요"


class Display:
    def __init__(self):
        self.values = {}
        self.rows = []

    def configure(self, **values):
        self.values.update(values)

    config = configure

    def winfo_exists(self):
        return True

    def get_children(self):
        return ()


def install_display(app):
    app.summary_title_label = Display()
    app.summary_tree = Display()
    app.notice_title_label = Display()
    app.notice_message_label = Display()
    app._insert_tree_row = lambda tree, *args, values, **kwargs: tree.rows.append(values)


def render(app):
    app.summary_tree.rows.clear()
    app._update_summary_title()
    app._update_summary_list()
    app._render_warning_state()
    return app.summary_title_label.values["text"], app.notice_title_label.values["text"]


def complete(app):
    app.current_tray.scanned_barcodes.append(f"{ITEM}-SERIAL-002")
    app.current_tray.scan_times.append(datetime.datetime.now())
    completed = []
    assert app.request_complete_tray(completion_callback=completed.append)
    _pump_until(app.root, lambda: bool(completed))
    assert completed == [True]
    return _details(_rows(app, "TRAY_COMPLETE")[0])


@pytest.mark.parametrize("partial", [False, True], ids=["full", "partial"])
def test_local_new_label_completion_shows_shipping_supplement(flow, partial):
    app = flow(transition=True, client=BlockingClient(
        _resolved(count=2), error=ConnectionError("fixture outage")))
    app._schedule_scanonly_transport = lambda **kwargs: None
    install_display(app)
    app._process_barcode_logic(COMPACT_QR + "|QT=2")
    _pump_until(app.root, lambda: bool(app.current_tray.master_label_code)
                and not app._preflight_hold_store().exists())
    _scan_products(app, 1 if partial else 2)
    if partial:
        app.submit_current_tray()
        assert GUIDANCE in app.warnings[-1][1]
        assert app._commit_short_confirmation()
    _pump_until(app.root, lambda: not app.current_tray.master_label_code)

    detail = _details(_rows(app, "TRAY_COMPLETE")[0])
    assert detail["transfer_seal_status"] == "PHS2_LOCAL_ONLY"
    title, notice = render(app)
    assert GUIDANCE in title and GUIDANCE in notice
    assert "보충 1건" in app.summary_tree.rows[0][2]
    assert not app._warning_state_presenter().state.is_blocking
    app._load_session_state()
    assert GUIDANCE in render(app)[0]


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_successful_central_seal_has_no_shipping_supplement(flow, tmp_path):
    app = _phs2_tray(flow, tmp_path, transition=True)
    install_display(app)
    app._prepare_and_attempt_transfer_seal_snapshot = lambda **kwargs: SealAttempt(
        "fixture-confirmed-completion", "ACKED", receipt_id="fixture-receipt")
    complete(app)

    assert all(GUIDANCE not in text for text in render(app))
    assert "보충" not in app.summary_tree.rows[0][2]


def test_legacy_completion_has_no_shipping_supplement(flow):
    app = flow(transition=True)
    install_display(app)
    app._process_barcode_logic(ITEM)
    _scan_products(app, 60)
    assert _details(_rows(app, "TRAY_COMPLETE")[0])["transition_class"] == "LEGACY"

    assert all(GUIDANCE not in text for text in render(app))
    assert "보충" not in app.summary_tree.rows[0][2]


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_late_receipt_clears_only_the_matching_tray_guidance(flow, tmp_path, monkeypatch):
    monkeypatch.setattr(session_history, "datetime", datetime)
    app = _phs2_tray(flow, tmp_path, transition=True)
    app._schedule_scanonly_transport = lambda **kwargs: None
    install_display(app)
    detail = complete(app)
    intent = detail["transfer_seal_intent_id"]
    assert GUIDANCE in render(app)[1]

    # A different tray's receipt cannot clear this completion.
    app._apply_transfer_coordinator_ui_snapshot({"shipping_confirmed_intents": ("other-tray",)})
    assert GUIDANCE in render(app)[1]
    app._apply_transfer_coordinator_ui_snapshot({"shipping_confirmed_intents": (intent,)})
    assert all(GUIDANCE not in text for text in render(app))
    assert "보충" not in app.summary_tree.rows[0][2]
    assert len(_rows(app, "TRAY_COMPLETE")) == 1

    # Rebuilding from the unchanged CSV must still respect the copied receipt.
    app._load_session_state()
    assert GUIDANCE not in render(app)[0]


@pytest.mark.parametrize("status", ["RETRY_WAIT", "OPERATOR_REVIEW", "ACKED", "missing"])
def test_receipt_snapshot_preserves_unconfirmed_guidance(status):
    app = ContainerAudit.__new__(ContainerAudit)
    app.work_summary = {ITEM: {"shipping_supplement_intents": {"fixture-tray"}}}

    def load(intent):
        assert intent == "fixture-tray"
        if status == "missing":
            raise LookupError("fixture unavailable")
        return {"status": status}

    store = SimpleNamespace(load=load, pending_ids=lambda: [], has_exact_history=lambda: False)
    app.transfer_seal_coordinator = SimpleNamespace(store=store, client=None)
    snapshot = app._work_transfer_coordinator_ui_snapshot()
    expected = ("fixture-tray",) if status == "ACKED" else ()
    assert snapshot["shipping_confirmed_intents"] == expected

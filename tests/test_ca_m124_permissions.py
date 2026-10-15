"""M124 preserves original evidence while separating worker and PIN effects."""
from pathlib import Path

import pytest

import Container_Audit as ca
import ca_screen_bridge as screen
from tests.test_container_admin_pin import SignedPinServer, make_headless_app
from tests.test_container_p0_contracts import _preflight_hold_ownership_app
from tests.test_supervisor_transfer_review_retry import _review_ui
from tests.operation_lease_fixtures import fixed_operation_lease_clock  # noqa: F401

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock")


@pytest.mark.parametrize("operation,action", [
    ("C02", "CA.PRECHECK_HOLD"), ("C03", "CA.PAIR_HANDOFF"),
    ("C04", "CA.PAIR_RETRY"), ("C04", "CA.TRAY_HOLD"),
    ("C05", "CA.TRAY_HOLD"), ("C09", "CA.PAIR_RETRY"),
])
def test_classified_worker_actions_keep_evidence_and_have_no_pin_or_approver(monkeypatch, tmp_path, operation, action):
    server = SignedPinServer()
    app, audits, _ = make_headless_app(monkeypatch, tmp_path, server)
    app.worker_name, app.worker_role = "m124-worker", "WORKER"
    app._prompt_blocked_work_admin_pin = lambda **_kw: pytest.fail("worker action requested credentials")
    source = {"original_revision": 1}
    approval = app._admin_pin_approval_for(action, "known-original", lambda: dict(source), (),
                                         lambda _intent: False, worker_operation=operation)
    assert approval and not server.calls
    identity = app._blocked_work_audit_identity(approval)
    assert identity["acting_worker"] == app.worker_name
    assert identity["acting_role"] == "WORKER"
    assert identity["approving_supervisor"] == identity["approving_role"] == ""
    assert identity["operation_key"] == approval["operation_key"]
    saved = app._admin_pin_store().read(approval["operation_key"])
    assert saved["state"] == "CONSUMED" and saved["source_snapshot"] == source
    assert saved["authorization_mode"] == "WORKER" and saved["worker_operation"] == operation
    assert saved["admin_id"] == saved["verification_id"] == ""
    assert app._admin_pin_complete(approval, lambda _intent: True)
    assert app._admin_pin_store().read(approval["operation_key"])["state"] == "APPLIED"
    assert any(event == "WORKER_ACTION_APPLIED" for event, _ in audits)
    assert not any(event == "ADMIN_PIN_APPLIED" for event, _ in audits)


def test_other_worker_cannot_resume_an_existing_worker_journal(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, _audits, _ = make_headless_app(monkeypatch, tmp_path, server)
    app.worker_name, app.worker_role = "record-owner", "WORKER"
    app._prompt_blocked_work_admin_pin = lambda **_kw: pytest.fail("worker action prompted")
    source = {"original": "preserved"}
    approve = lambda: app._admin_pin_approval_for(
        "CA.TRAY_HOLD", "same-target", lambda: dict(source), (),
        lambda _intent: False, worker_operation="C05")
    first = approve()
    assert first
    path = app._admin_pin_store().path(first["operation_key"])
    before = path.read_bytes()
    app.worker_name = "other-worker"
    assert approve() is None
    assert path.read_bytes() == before
    assert not server.calls


def test_worker_source_change_never_authorizes_the_changed_original(monkeypatch, tmp_path):
    app, _audits, _ = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    app.worker_name, app.worker_role = "m124-worker", "WORKER"
    calls = []
    def source():
        calls.append(1)
        return {"original_revision": 1 if len(calls) == 1 else 2}
    assert app._admin_pin_approval_for("CA.TRAY_HOLD", "known-original", source, (),
                                     lambda _intent: False, worker_operation="C05") is None
    saved = app._admin_pin_store().list_pending()
    assert len(saved) == 1 and saved[0]["state"] == "TARGET_CHANGED"
    assert saved[0]["source_snapshot"] == {"original_revision": 1}


def test_unclassified_effect_still_requires_pin(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, _audits, _ = make_headless_app(monkeypatch, tmp_path, server)
    app.worker_name, app.worker_role = "m124-worker", "WORKER"
    asked = []
    app._prompt_blocked_work_admin_pin = lambda **_kw: asked.append(1) or None
    assert app._admin_pin_approval_for("CA.PAIR_HANDOFF", "unidentified-original", lambda: {}, (),
                                     lambda _intent: False) is None
    assert asked == [1] and not server.calls
    assert not app._admin_pin_store().list_pending()
    assert app._admin_pin_approval_for("CA.PAIR_HANDOFF", "unidentified-original", lambda: {}, (),
                                     lambda _intent: False, worker_operation="C05") is None
    assert asked == [1]


def test_worker_menu_routes_without_pin_and_admin_menu_cannot_use_command(monkeypatch):
    app = object()
    called = []
    monkeypatch.setattr(screen, "operations_menu", lambda _app: {
        name: (True, lambda key=name: called.append(key) or True) for name in screen.ADMIN_MENU})
    processor = screen.CaProcessor(app)
    for name in screen.WORKER_MENU:
        assert processor.command(name)["ok"]
    assert set(called) == set(screen.WORKER_MENU)
    assert not processor.command("list_paired")["ok"]
    assert not processor.admin("list_paired", {})["ok"]
    assert "list_paired" not in called


@pytest.mark.parametrize("lost_restore_audit", [False, True])
def test_own_precheck_hold_preserves_bytes_without_pin_but_restore_still_requires_it(monkeypatch, tmp_path, lost_restore_audit):
    _module, app, hold = _preflight_hold_ownership_app(tmp_path, monkeypatch)
    app.worker_name, app.worker_role = "m124-worker", "WORKER"
    app._authenticated_protected_admin = False
    app._admin_pin_login_epoch = "m124-test-epoch"
    app.CURRENT_TRAY_STATE_FILE = "m124-current.json"
    app.local_events_folder = app.save_folder
    events, asked = [], []
    app._log_event = lambda event, **kwargs: events.append((event, kwargs)) or True
    app._admin_pin_effect_audited = lambda event, key: any(
        name == event and row.get("detail", {}).get("operation_key") == key for name, row in events)
    app._prompt_blocked_work_admin_pin = lambda **_kw: asked.append(1) or None
    app._admin_pin_client_for_work = lambda: pytest.fail("worker hold contacted PIN service")
    hold.start(worker=app.worker_name, master_raw="m124-known-label", scan_epoch=1)
    hold.append("m124-original-product")
    hold.mark_failed(error_code="M124_LOOKUP_FAILED")
    app._preflight_hold_snapshot = hold.load()
    original = hold.path.read_bytes()
    assert app._quarantine_preflight_hold_for_supervisor(reason="worker_next_tray", confirm=False)
    assert asked == [] and not hold.path.exists()
    saved = next(app._preflight_hold_quarantine_directory().glob("*.json"))
    assert saved.read_bytes() == original
    assert not app.restore_quarantined_preflight_hold(str(saved), confirm=False)
    assert asked == [1] and saved.read_bytes() == original and not hold.path.exists()
    server = SignedPinServer()
    credential_app, _audits, _notices = make_headless_app(monkeypatch, tmp_path / "administrator", server)
    app._admin_pin_client_for_work = lambda: credential_app._admin_pin_client
    app._prompt_blocked_work_admin_pin = credential_app._prompt_blocked_work_admin_pin
    if lost_restore_audit:
        audit = app._log_event
        class InterruptedRestore(BaseException):
            pass
        def interrupted_audit(event, **kwargs):
            if event == "PHS2_PREFLIGHT_HOLD_RESTORED":
                raise InterruptedRestore()
            return audit(event, **kwargs)
        app._log_event = interrupted_audit
        with pytest.raises(InterruptedRestore):
            app.restore_quarantined_preflight_hold(str(saved), confirm=False)
        assert not saved.exists() and hold.path.read_bytes() == original
        app._log_event = audit
        app._prompt_blocked_work_admin_pin = lambda **_kw: pytest.fail("consumed restore prompted again")
    assert app.restore_quarantined_preflight_hold(str(saved), confirm=False)
    if not lost_restore_audit:
        assert len(server.calls) == 2
    assert not saved.exists() and hold.path.read_bytes() == original
    restore_rows = [row for row in app._admin_pin_store().list_pending()
                    if row.get("source_snapshot", {}).get("restore_preflight_id")]
    assert len(restore_rows) == 1 and restore_rows[0]["state"] == "APPLIED"
    assert restore_rows[0]["verification_id"] and restore_rows[0]["admin_id"]


def test_worker_recheck_finishes_same_journal_without_pin_service(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, audits, _ = make_headless_app(monkeypatch, tmp_path, server)
    app.worker_name, app.worker_role = "m124-worker", "WORKER"
    app._prompt_blocked_work_admin_pin = lambda **_kw: pytest.fail("worker recheck requested credentials")
    source = {"original_revision": 1}
    approval = app._admin_pin_approval_for("CA.TRAY_HOLD", "known-original", lambda: dict(source), (),
                                         lambda _intent: False, worker_operation="C05")
    key = approval["operation_key"]
    original = app._admin_pin_store().read(key)
    app._admin_pin_login_epoch = "next-test-login"
    second = app._admin_pin_approval_for("CA.TRAY_HOLD", "known-original", lambda: dict(source), (),
                                       lambda _intent: False, worker_operation="C05")
    assert second["operation_key"] == key
    current = app._admin_pin_store().read(key)
    assert current["operator"] == original["operator"]
    assert current["source_snapshot"] == original["source_snapshot"]
    app._admin_pin_recovered_effect = lambda _intent: True
    released = []
    app._admin_pin_release_completed_work = lambda intent, **_kw: released.append(intent["operation_key"])
    assert app._run_durable_ui_steps(app._recheck_admin_pin_intent_steps()) is None
    assert released == [key] and not server.calls
    assert app._admin_pin_store().read(key)["state"] == "APPLIED"


def test_worker_completion_retry_reuses_the_command_and_leaves_approver_blank(tmp_path, monkeypatch):
    app, lane, audit, posted, coordinator, intent_id, _messages = _review_ui(tmp_path, monkeypatch, role="WORKER")
    before = coordinator.store.load(intent_id)
    command = before["command_json"]
    key = before["idempotency_key"]
    assert app._retry_transfer_post_review()
    result = lane.tasks[0].work()
    lane.tasks[0].finish(result)
    after = coordinator.store.load(intent_id)
    assert after["command_json"] == command and after["idempotency_key"] == key
    detail = audit[0][1]["detail"]
    assert detail["acting_worker"] == app.worker_name and detail["acting_role"] == "WORKER"
    assert detail["supervisor"] == detail["approving_supervisor"] == detail["approving_role"] == ""
    assert len(posted) == 2


def test_worker_preserves_a_stale_current_original_without_pin(monkeypatch, tmp_path):
    from tests.test_paired_preflight_handoff import _app
    app, _hold, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations()
    stale = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    ca.atomic_write_json(stale, current)
    original = stale.read_bytes()
    quarantine = app._quarantine_current_tray_state
    app._quarantine_current_tray_state = lambda _reason: None
    app._load_current_tray_state()
    assert app._paired_stale_current_blocked
    app._quarantine_current_tray_state = quarantine
    app._admin_pin_login_epoch = "m124-stale-test"
    app._admin_pin_approval_for = ca.ContainerAudit._admin_pin_approval_for.__get__(app)
    app._admin_pin_complete = ca.ContainerAudit._admin_pin_complete.__get__(app)
    app._prompt_blocked_work_admin_pin = lambda **_kw: pytest.fail("worker preservation requested credentials")
    app._admin_pin_client_for_work = lambda: pytest.fail("worker preservation contacted PIN service")
    assert app._retry_paired_stale_current_preservation()
    preserved = Path(app._paired_stale_current_preserved_path)
    assert preserved.read_bytes() == original and not stale.exists()
    records = [row for row in app._admin_pin_store().list_pending() if row.get("worker_operation") == "C04"]
    assert len(records) == 1 and records[0]["state"] == "APPLIED"
    assert records[0]["admin_id"] == records[0]["verification_id"] == ""

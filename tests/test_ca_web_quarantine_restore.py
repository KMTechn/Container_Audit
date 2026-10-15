"""Web C08/C12 uses a fresh, source-bound PIN request after confirmation."""
import hashlib
import json
import threading
import uuid
from types import SimpleNamespace

import pytest

import ca_screen_bridge as screen
import writer_session_fence as fence
from tests.test_admin_pin_move_timing import _business_case
from tests.test_admin_pin_ui_lane import PinRoot
from tests.test_container_admin_pin import make_client


@pytest.fixture
def restore_case(monkeypatch, tmp_path):
    app, server, audits, original, label, quarantine = _business_case(
        monkeypatch, tmp_path, "CA.PRECHECK_HOLD")
    original_bytes = original.read_bytes()
    assert quarantine()
    held = next(app._preflight_hold_quarantine_directory().glob("*.json"))
    assert held.read_bytes() == original_bytes and not server.calls
    root = PinRoot()
    app.root = root
    app._schedule_focus_return = lambda: None
    app.scan_entry = None
    processor = screen.CaProcessor(app)
    monkeypatch.setattr(screen, "operations_menu", lambda _app: {
        "list_paired": (True, app._show_paired_preflight_handoffs)})
    pin = str(uuid.uuid4().int % 1000000).zfill(6)
    threads = []

    def transport(path, body, headers):
        threads.append(threading.get_ident())
        assert threading.get_ident() != root.owner_thread_id
        assert not getattr(fence._WRITER_LOCAL, "depth", 0)
        request = json.loads(body)
        if path.endswith("/verifications") and request["pin"] != pin:
            return 403, json.dumps({"ok": False, "error": {"code": "PIN_INVALID"}}).encode()
        return server(path, body, headers)

    app._admin_pin_client = make_client(monkeypatch, transport)
    processor.install()
    case = SimpleNamespace()
    case.app, case.server, case.audits = app, server, audits
    case.original, case.held, case.original_bytes = original, held, original_bytes
    case.root, case.processor, case.pin, case.threads = root, processor, pin, threads
    try:
        yield case
    finally:
        root.run_until(lambda: not getattr(app, "_admin_pin_ui_pending", False))
        processor.shutdown()


def _credentials(case, **extra):
    return {"admin_id": "restore-admin", "pin": case.pin, **extra}


def _confirm(case):
    processor = case.processor
    processor.admin("list_paired", _credentials(case))
    assert processor._credentials is None
    assert case.held.read_bytes() == case.original_bytes and not case.server.calls
    assert case.app._inline_scan_choices
    assert processor.command("choose", {"id": "choice-0"})["ok"]
    assert not case.server.calls and processor._credentials is None
    sheet = processor.sheet
    assert sheet and sheet["kind"] == "info"
    go = sheet["actions"][0]["go"]
    prefix = "open:list_paired:"
    assert go.startswith(prefix)
    assert case.pin not in json.dumps(sheet)
    from tests.test_ca_screen_bridge import CONTRACT, _schema_errors
    state = processor.state()
    assert not _schema_errors(state, CONTRACT["state"])
    assert case.pin not in json.dumps(state)
    menu = next(row for row in state["admin_menu"] if row["name"] == "list_paired")
    assert menu["facts"] == sheet["facts"]
    return go[len(prefix):]


def _settle(case):
    case.root.run_until(lambda: not getattr(case.app, "_admin_pin_ui_pending", False))
    assert not case.app._ui_task_lane().is_busy()


def test_web_confirmation_gets_a_separate_pin_and_restores_exact_bytes(restore_case):
    case = restore_case
    target = _confirm(case)
    assert case.processor.admin("list_paired", _credentials(case, target=target))["ok"]
    assert case.processor._credentials is None
    _settle(case)
    assert case.original.read_bytes() == case.original_bytes and not case.held.exists()
    assert [path.rsplit("/", 1)[-1] for path, _ in case.server.calls] == ["verifications", "redemptions"]
    assert set(case.threads) == {case.app._ui_lane.worker_thread_id}
    assert case.processor.sheet is None
    intent = next(row for row in case.app._admin_pin_store().list_pending()
                  if row.get("source_snapshot", {}).get("quarantine_source"))
    assert intent["state"] == "APPLIED"
    assert intent["target"]["id"] == "restore-" + hashlib.sha256(case.original_bytes).hexdigest()
    assert case.pin not in case.app._admin_pin_store().path(intent["operation_key"]).read_text()
    before = len(case.server.calls)
    assert not case.processor.admin("list_paired", _credentials(case, target=target))["ok"]
    assert len(case.server.calls) == before


@pytest.mark.parametrize("credential", ["missing", "wrong"])
def test_web_restore_refuses_missing_or_wrong_pin(restore_case, credential):
    case = restore_case
    target = _confirm(case)
    args = {"target": target} if credential == "missing" else _credentials(
        case, target=target, pin=str((int(case.pin) + 1) % 1000000).zfill(6))
    case.processor.admin("list_paired", args)
    if credential == "wrong":
        _settle(case)
    assert not case.original.exists() and case.held.read_bytes() == case.original_bytes
    assert not case.server.consumed


@pytest.mark.parametrize("change", ["worker", "source", "source_during_submit", "target", "cancel"])
def test_web_restore_request_cannot_authorize_another_identity_or_source(restore_case, monkeypatch, change):
    case = restore_case
    target = _confirm(case)
    if change == "worker":
        case.app.worker_name += "-other"
    elif change == "source":
        case.held.write_bytes(case.original_bytes + b" ")
    elif change == "target":
        target = uuid.uuid4().hex
    elif change == "source_during_submit":
        submit = case.app._submit_admin_pin_steps

        def changed_before_start(steps, name):
            case.held.write_bytes(case.original_bytes + b" ")
            return submit(steps, name)

        monkeypatch.setattr(case.app, "_submit_admin_pin_steps", changed_before_start)
    else:
        assert case.processor.command("close")["ok"]
    preserved = case.held.read_bytes()
    assert not case.processor.admin("list_paired", _credentials(case, target=target))["ok"]
    assert not case.server.calls and not case.original.exists()
    assert case.held.read_bytes() == (preserved + b" " if change == "source_during_submit" else preserved)


@pytest.mark.parametrize("after_move", [False, True])
def test_web_consumed_restore_resumes_the_same_request_without_another_pin(restore_case, monkeypatch, after_move):
    from preflight_scan_hold import PreflightScanHoldStore

    case = restore_case
    target = _confirm(case)
    restore = PreflightScanHoldStore.restore_quarantined
    stopped = []

    def interrupted(store, path):
        if not stopped:
            stopped.append(True)
            if after_move:
                restore(store, path)
            raise OSError("injected interruption after PIN consumption")
        return restore(store, path)

    monkeypatch.setattr(PreflightScanHoldStore, "restore_quarantined", interrupted)
    case.processor.admin("list_paired", _credentials(case, target=target))
    _settle(case)
    assert case.server.consumed
    preserved = case.original if after_move else case.held
    assert preserved.read_bytes() == case.original_bytes
    intent = next(row for row in case.app._admin_pin_store().list_pending()
                  if row.get("source_snapshot", {}).get("quarantine_source"))
    operation_key = intent["operation_key"]
    assert intent["state"] == "CONSUMED"
    owner = case.app.worker_name
    case.app.worker_name += "-other"
    before = len(case.server.calls)
    assert not case.processor.admin("list_paired", _credentials(case, target=target))["ok"]
    assert len(case.server.calls) == before and preserved.read_bytes() == case.original_bytes
    case.app.worker_name = owner
    case.processor.admin("list_paired", _credentials(case, target=target))
    _settle(case)
    saved = case.app._admin_pin_store().read(operation_key)
    assert saved["state"] == "APPLIED"
    assert case.original.read_bytes() == case.original_bytes and not case.held.exists()
    assert sum(path.endswith("/verifications") for path, _ in case.server.calls) == 1
    assert sum(path.endswith("/redemptions") for path, _ in case.server.calls) == 1

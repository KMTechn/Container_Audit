"""Headless contract checks for per-operation CA administrator PIN evidence."""

import hashlib
import hmac
import json
import uuid
import csv
from pathlib import Path
from types import SimpleNamespace

import pytest

import container_admin_pin as pin


class SignedPinServer:
    def __init__(self):
        self.calls = []
        self.used_nonces = set()
        self.verification_id = str(uuid.uuid4())
        self.redemption_id = str(uuid.uuid4())
        self.drop_redemption_once = False
        self.consumed = False

    def __call__(self, path, body, headers):
        digest = hashlib.sha256(body).hexdigest()
        signed = "\n".join((
            pin.SIGNATURE_VERSION, "POST", path, "",
            headers["X-Producer-Timestamp"], headers["X-Producer-Nonce"],
            headers["X-Producer-Id"], headers["X-Producer-Key-Id"], digest, digest,
            str(len(body)), "application/json",
        ))
        expected = hmac.new(b"test-secret", signed.encode(), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(expected, headers["X-Producer-Signature"])
        assert headers["X-Producer-Nonce"] not in self.used_nonces
        self.used_nonces.add(headers["X-Producer-Nonce"])
        request = json.loads(body)
        self.calls.append((path, request))
        if path.endswith("/verifications"):
            response = {"ok": True, "verification_id": self.verification_id,
                        "proof": "test-proof", "issued_at": 1000, "expires_at": 1180,
                        "admin_id": request["admin_id"], "action": request["action"],
                        "target_fingerprint": request["target"]["state_fingerprint"],
                        "device_ref": "install:host", "request_id": request["request_id"]}
            return 201, json.dumps(response).encode()
        if path.endswith("/redemptions"):
            self.consumed = True
            if self.drop_redemption_once:
                self.drop_redemption_once = False
                raise TimeoutError("response lost after commit")
            return 200, json.dumps({"ok": True, "verification_id": self.verification_id,
                                    "operation_key": request["operation_key"],
                                    "redemption_id": self.redemption_id,
                                    "consumed_at": 1001}).encode()
        if path.endswith("/status"):
            return 200, json.dumps({"ok": True, "verification_id": self.verification_id,
                                    "operation_key": request["operation_key"],
                                    "status": "CONSUMED" if self.consumed else "UNUSED",
                                    **({"redemption_id": self.redemption_id, "consumed_at": 1001}
                                       if self.consumed else {})}).encode()
        raise AssertionError(path)


def make_client(monkeypatch, server):
    monkeypatch.setattr(pin, "load_credentials_from_json", lambda _path: SimpleNamespace(
        endpoint_url="https://pin.example.test/api/producer-ingest/v1",
        producer_id="producer", key_id="key", secret="test-secret",
        tls_ca_bundle_path="",
    ))
    return pin.AdminPinClient("unused", transport=server)


def pin_inputs():
    return {"request_id": str(uuid.uuid4()), "admin_id": "manager-1", "pin": "194826",
            "action": "CA.PRECHECK_HOLD",
            "target": {"kind": "precheck_hold", "id": "target-1",
                       "state_fingerprint": "a" * 64},
            "operator": {"local_id": "worker-1", "login_epoch": uuid.uuid4().hex}}


def test_signed_verification_redemption_loss_uses_same_key_status(monkeypatch):
    server = SignedPinServer()
    server.drop_redemption_once = True
    client = make_client(monkeypatch, server)
    request = pin_inputs()
    result = client.verify(**request)
    operation_key = str(uuid.uuid4())
    client.redeem(verification_id=result["verification_id"], proof=result["proof"],
                  operation_key=operation_key, action=request["action"],
                  target=request["target"], operator=request["operator"])
    assert [path.rsplit("/", 1)[-1] for path, _ in server.calls] == [
        "verifications", "redemptions", "status"]
    assert len(server.used_nonces) == 3
    assert server.calls[-1][1]["operation_key"] == operation_key


def test_incomplete_success_is_unknown(monkeypatch):
    server = SignedPinServer()
    def incomplete(path, body, headers):
        status, raw = server(path, body, headers)
        if path.endswith("/verifications"):
            response = json.loads(raw)
            response.pop("request_id")
            return status, json.dumps(response).encode()
        return status, raw
    client = make_client(monkeypatch, incomplete)
    with pytest.raises(pin.AdminPinError) as raised:
        client.verify(**pin_inputs())
    assert raised.value.unknown


def test_verify_retries_busy_once_but_never_retries_offline(monkeypatch):
    server = SignedPinServer()
    calls = {"busy": 0, "offline": 0}
    def busy_once(path, body, headers):
        calls["busy"] += 1
        if calls["busy"] == 1:
            return 503, b'{"error":{"code":"PIN_BUSY"}}'
        return server(path, body, headers)
    assert make_client(monkeypatch, busy_once).verify(**pin_inputs())["proof"]
    assert calls["busy"] == 2
    def offline(_path, _body, _headers):
        calls["offline"] += 1
        raise TimeoutError("offline")
    with pytest.raises(pin.AdminPinError):
        make_client(monkeypatch, offline).verify(**pin_inputs())
    assert calls["offline"] == 1


@pytest.mark.parametrize("route", ("redemptions", "status"))
def test_incomplete_redemption_or_status_is_unknown(monkeypatch, route):
    server = SignedPinServer()
    def incomplete(path, body, headers):
        status, raw = server(path, body, headers)
        if path.endswith("/" + route):
            response = json.loads(raw)
            response.pop("operation_key")
            return status, json.dumps(response).encode()
        return status, raw
    client = make_client(monkeypatch, incomplete)
    request = pin_inputs()
    verification = client.verify(**request)
    key = str(uuid.uuid4())
    with pytest.raises(pin.AdminPinError) as raised:
        if route == "redemptions":
            client.redeem(verification_id=verification["verification_id"],
                          proof=verification["proof"], operation_key=key,
                          action=request["action"], target=request["target"],
                          operator=request["operator"])
        else:
            client.status(verification["verification_id"], key)
    assert raised.value.unknown


def test_intent_keeps_secret_out_and_parked_key_evidence(tmp_path):
    from label_qr import canonical_master_label_key
    from parked_tray_store import ParkedTrayStore

    label = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-PIN|CLC=AAA2270730100|LBL=PIN|HSH=0123456789abcdef"
    other = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-OTHER|CLC=AAA2270730100|LBL=OTHER|HSH=0123456789abcdef"
    store = pin.AdminPinIntentStore(tmp_path / "parked_trays" / "admin_pin_intents")
    key = str(uuid.uuid4())
    target_id = hashlib.sha256(canonical_master_label_key(label).encode()).hexdigest()
    record = {"operation_key": key, "target": {"id": target_id},
              "action": "CA.TRAY_HOLD", "state": "UNVERIFIED_OPERATOR_HOLD",
              "labels": [label], "verification_id": "", "reason": "VERIFY_UNAVAILABLE"}
    store.write(record)
    assert store.read(key) == record
    assert b"proof" not in store.path(key).read_bytes()
    assert store.pending("CA.TRAY_HOLD", target_id) == [record]
    evidence = ParkedTrayStore(tmp_path / "parked_trays").enumerate_key_evidence()
    assert len(evidence) == 1 and evidence[0].kind == "pin_intent"
    assert evidence[0].binds(label) and not evidence[0].binds(other)
    with pytest.raises(ValueError):
        store.write(dict(record, pin="123456"))
    store.transition(record, "APPLIED")
    assert not ParkedTrayStore(tmp_path / "parked_trays").enumerate_key_evidence()


def test_operator_id_is_stable_and_web_safe():
    assert pin.operator_local_id(" worker-1 ") == "worker-1"
    assert pin.operator_local_id(" 작업자 ").startswith("wn:")
    assert pin.operator_local_id("가" * 64).startswith("wh:")


def test_operator_original_and_sent_id_are_audited_without_secret(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    app.worker_name = "작업자 김"
    source = lambda: {"version": 1}
    approval = app._admin_pin_approval_for(
        "CA.PAIR_RETRY", "a" * 64, source, (), lambda _intent: False)
    assert approval is not None
    intent = app._admin_pin_store().read(approval["operation_key"])
    sent = pin.operator_local_id("작업자 김")
    assert intent["operator_raw"] == "작업자 김"
    assert intent["operator"]["local_id"] == sent
    consumed = next(kwargs["detail"] for event, kwargs in audits if event == "ADMIN_PIN_CONSUMED")
    assert consumed["operator_raw"] == "작업자 김"
    assert consumed["operator"]["local_id"] == sent
    verified_request = next(body for path, body in server.calls if path.endswith("/verifications"))
    assert verified_request["operator"] == intent["operator"]
    assert "operator_raw" not in verified_request
    app.worker_name = "재개 작업자"
    app._admin_pin_login_epoch = uuid.uuid4().hex
    assert app._admin_pin_approval_for(
        "CA.PAIR_RETRY", "a" * 64, source, (), lambda _intent: False) is not None
    resumed = app._admin_pin_store().read(approval["operation_key"])
    assert resumed["resuming_operator_raw"] == "재개 작업자"
    resume_detail = next(kwargs["detail"] for event, kwargs in audits if event == "ADMIN_PIN_RESUMED")
    assert resume_detail["resuming_operator_raw"] == "재개 작업자"
    assert resume_detail["resuming_operator"]["local_id"] == pin.operator_local_id("재개 작업자")
    assert b"194826" not in app._admin_pin_store().path(approval["operation_key"]).read_bytes()
    assert b"test-proof" not in app._admin_pin_store().path(approval["operation_key"]).read_bytes()


def test_damaged_other_key_does_not_block_healthy_key(tmp_path):
    store = pin.AdminPinIntentStore(tmp_path / "intents")
    first = {"operation_key": str(uuid.uuid4()), "target": {"id": "a" * 64},
             "action": "CA.TRAY_HOLD", "state": "CONSUMED"}
    second = {"operation_key": str(uuid.uuid4()), "target": {"id": "b" * 64},
              "action": "CA.TRAY_HOLD", "state": "CONSUMED"}
    store.write(first)
    store.write(second)
    store.path(first["operation_key"]).write_bytes(b"{damaged")
    assert store.pending("CA.TRAY_HOLD", "b" * 64) == [second]
    with pytest.raises(ValueError):
        store.pending("CA.TRAY_HOLD", "a" * 64)


def make_headless_app(monkeypatch, tmp_path, server):
    from Container_Audit import ContainerAudit
    from Container_Audit import messagebox

    app = object.__new__(ContainerAudit)
    app.worker_name = "worker-1"
    app.worker_role = "WORKER"
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app.parked_trays_dir = str(tmp_path / "parked_trays")
    app._admin_pin_client = make_client(monkeypatch, server)
    app._prompt_blocked_work_admin_pin = lambda: ("manager-1", "194826")
    audits = []
    app._log_event = lambda event, **kwargs: audits.append((event, kwargs)) or True
    notices = []
    monkeypatch.setattr(messagebox, "showwarning", lambda *args, **kwargs: notices.append(args))
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: notices.append(args))
    monkeypatch.setattr(messagebox, "showinfo", lambda *args, **kwargs: notices.append(args))
    monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: True)
    return app, audits, notices


def assert_other_phs2_starts(app, blocked_label):
    from Container_Audit import TraySession

    other = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-FREE|CLC=AAA2270730100|LBL=FREE|HSH=0123456789abcdef"
    assert not app._preflight_context_blocks_mutation()
    assert not app._scan_entry_admission_block_reason()
    assert app._paired_preflight_blocks_label(blocked_label)
    app.current_tray = TraySession()
    app.is_idle = False
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app._intercept_phs_reconciliation_scan = lambda _value: False
    app._intercept_active_tray_phs2_scan = lambda _value: False
    app._is_completed_master_label = lambda _value: False
    app._item_catalog = lambda: SimpleNamespace(
        find_by_code=lambda _code: {"Item Code": "AAA2270730100"})
    app.show_fullscreen_warning = lambda *_args: None
    started = []
    app._begin_compact_phs2_preflight = lambda **kwargs: started.append(kwargs["barcode"])
    app._process_barcode_logic(blocked_label)
    app._process_barcode_logic(other)
    assert started == [other]


def offline_passive_app(monkeypatch, tmp_path):
    from Container_Audit import TraySession, WarningPresenter

    def offline(*_args):
        raise TimeoutError("offline")
    app, _audits, _notices = make_headless_app(monkeypatch, tmp_path, offline)
    app.save_folder = str(tmp_path / "events")
    app.local_events_folder = str(tmp_path / "local_events")
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.PREFLIGHT_SCAN_HOLD_FILE = "hold.json"
    app.TRAY_SIZE = 60
    app.computer_id = "test-host"
    app.current_tray = TraySession()
    app.warning_presenter = WarningPresenter()
    return app


def test_headless_consumed_intent_resumes_same_key_before_writer(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    state = {"version": 1}
    applied = {"value": False}
    source = lambda: dict(state)
    effect = lambda _intent: applied["value"]
    first = app._admin_pin_approval_for("CA.TRAY_HOLD", "b" * 64,
                                        source, ("PHS2-original",), effect)
    assert first is not None
    assert app._admin_pin_store().read(first["operation_key"])["state"] == "CONSUMED"
    second = app._admin_pin_approval_for("CA.TRAY_HOLD", "b" * 64,
                                         source, ("PHS2-original",), effect)
    assert second["operation_key"] == first["operation_key"]
    assert [path.rsplit("/", 1)[-1] for path, _ in server.calls] == [
        "verifications", "redemptions", "status"]
    applied["value"] = True
    assert app._admin_pin_complete(second, effect)
    assert app._admin_pin_store().read(first["operation_key"])["state"] == "APPLIED"
    assert [row[0] for row in audits].count("ADMIN_PIN_APPLIED") == 1


def test_consumed_partial_resumes_after_login_epoch_change(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    source = lambda: {"version": 1}
    effect = lambda _intent: False
    first = app._admin_pin_approval_for("CA.PAIR_RETRY", "a" * 64, source, (), effect)
    app.worker_name = "worker-2"
    app._admin_pin_login_epoch = uuid.uuid4().hex
    second = app._admin_pin_approval_for("CA.PAIR_RETRY", "a" * 64, source, (), effect)
    assert second["operation_key"] == first["operation_key"]
    assert app._admin_pin_store().read(first["operation_key"])["resuming_operator"] == {
        "local_id": "worker-2", "login_epoch": app._admin_pin_login_epoch}
    assert [event for event, _ in audits].count("ADMIN_PIN_RESUMED") == 1
    assert len([path for path, _ in server.calls if path.endswith("/redemptions")]) == 1


def test_login_change_after_redemption_keeps_consumed_key_for_new_operator(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    original_check = app._blocked_work_identity_is_current
    changed = {"once": True}
    def identity(approval):
        if changed["once"]:
            changed["once"] = False
            return False
        return original_check(approval)
    app._blocked_work_identity_is_current = identity
    source = lambda: {"version": 1}
    first = app._admin_pin_approval_for(
        "CA.PAIR_RETRY", "a" * 64, source, (), lambda _intent: False)
    assert first is None
    pending = app._admin_pin_store().pending("CA.PAIR_RETRY", "a" * 64)
    assert len(pending) == 1 and pending[0]["state"] == "CONSUMED"
    app.worker_name = "worker-2"
    app._admin_pin_login_epoch = uuid.uuid4().hex
    second = app._admin_pin_approval_for(
        "CA.PAIR_RETRY", "a" * 64, source, (), lambda _intent: False)
    assert second["operation_key"] == pending[0]["operation_key"]
    assert [event for event, _ in audits].count("ADMIN_PIN_RESUMED") == 1
    assert len([path for path, _ in server.calls if path.endswith("/redemptions")]) == 1


def test_consumed_missing_target_closes_unknown_and_keeps_key(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    current = {"present": True}
    def source():
        if not current["present"]:
            raise OSError("original disappeared")
        return {"version": 1}
    app._preflight_hold_store = lambda: SimpleNamespace(path=tmp_path / "missing-hold.json")
    first = app._admin_pin_approval_for("CA.PRECHECK_HOLD", "a" * 64,
                                        source, (), lambda _intent: False)
    current["present"] = False
    assert app._admin_pin_approval_for("CA.PRECHECK_HOLD", "a" * 64,
                                       source, (), lambda _intent: False) is None
    saved = app._admin_pin_store().read(first["operation_key"])
    assert saved["state"] == "HANDED_OFF_UNKNOWN"
    assert saved["operation_key"] == first["operation_key"]
    assert [event for event, _ in audits].count("ADMIN_PIN_HANDOFF_UNKNOWN") == 1


def test_changed_target_after_consumption_never_reaches_writer(monkeypatch, tmp_path):
    state = {"version": 1}
    server = SignedPinServer()
    def change_after_redeem(path, body, headers):
        response = server(path, body, headers)
        if path.endswith("/redemptions"):
            state["version"] = 2
        return response
    app, audits, notices = make_headless_app(monkeypatch, tmp_path, change_after_redeem)
    approval = app._admin_pin_approval_for(
        "CA.PRECHECK_HOLD", "c" * 64, lambda: dict(state),
        ("PHS2-original",), lambda _intent: False,
    )
    assert approval is None
    pending = app._admin_pin_store().pending("CA.PRECHECK_HOLD", "c" * 64)
    assert len(pending) == 1 and pending[0]["state"] == "HANDED_OFF_UNKNOWN"
    assert pending[0]["reason"] == "EFFECT_UNVERIFIED"
    assert [row[0] for row in audits] == ["ADMIN_PIN_HANDOFF_UNKNOWN"]
    assert notices


def test_changed_target_on_consumed_status_hands_off_original_key(monkeypatch, tmp_path):
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    state = {"version": 1}
    source = lambda: dict(state)
    first = app._admin_pin_approval_for(
        "CA.PAIR_RETRY", "c" * 64, source, (), lambda _intent: False)
    state["version"] = 2
    assert app._admin_pin_approval_for(
        "CA.PAIR_RETRY", "c" * 64, source, (), lambda _intent: False) is None
    saved = app._admin_pin_store().read(first["operation_key"])
    assert saved["state"] == "HANDED_OFF_UNKNOWN"
    assert saved["operation_key"] == first["operation_key"]
    assert [event for event, _ in audits].count("ADMIN_PIN_HANDOFF_UNKNOWN") == 1


@pytest.mark.parametrize("admin_id, secret", (("manager-1", "12345x"), ("", "654321")))
def test_pin_format_rejection_is_audited_without_saving_secret(monkeypatch, tmp_path,
                                                                 admin_id, secret):
    server = SignedPinServer()
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    app._prompt_blocked_work_admin_pin = lambda: (admin_id, secret)
    approval = app._admin_pin_approval_for(
        "CA.TRAY_HOLD", "d" * 64, lambda: {"version": 1}, (), lambda _intent: False)
    assert approval is None and server.calls == []
    assert [event for event, _ in audits] == ["ADMIN_PIN_REJECTED"]
    assert all(secret not in json.dumps(kwargs) for _event, kwargs in audits)
    assert app._admin_pin_store().pending("CA.TRAY_HOLD", "d" * 64) == []
    for path in (tmp_path / "parked_trays" / "admin_pin_intents").glob("*.json"):
        assert secret.encode() not in path.read_bytes() and b"proof" not in path.read_bytes()


def test_cancelled_pin_prompt_does_not_create_retry_or_reopen(monkeypatch, tmp_path):
    server = SignedPinServer()
    app, _audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    calls = []
    app._prompt_blocked_work_admin_pin = lambda: calls.append("prompt") or None
    assert app._admin_pin_approval_for(
        "CA.TRAY_HOLD", "d" * 64, lambda: {"version": 1}, (),
        lambda _intent: False) is None
    assert calls == ["prompt"] and server.calls == []
    assert app._admin_pin_store().list_pending() == []


def test_recheck_menu_remains_visible_over_unrelated_blocking_warning(monkeypatch):
    from Container_Audit import ContainerAudit, TraySession, tk

    app = object.__new__(ContainerAudit)
    app.root = SimpleNamespace()
    app.current_tray = TraySession()
    app.operations_button = SimpleNamespace(
        winfo_rootx=lambda: 1, winfo_rooty=lambda: 2, winfo_height=lambda: 3)
    app._preflight_context_blocks_mutation = lambda: False
    app._active_blocking_completion_snapshot = lambda: None
    app._current_transfer_member_exchange_attempt = lambda: None
    app._warning_state_presenter = lambda: SimpleNamespace(
        state=SimpleNamespace(is_blocking=True))
    app._admin_pin_has_pending = lambda: True
    shown = []
    class Menu:
        def __init__(self, *_args, **_kwargs):
            pass
        def add_command(self, **kwargs):
            shown.append(kwargs["label"])
        def tk_popup(self, *_args):
            shown.append("opened")
        def grab_release(self):
            pass
    monkeypatch.setattr(tk, "Menu", Menu)
    app._show_operations_menu()
    assert shown == ["관리자 확인 다시 조회", "opened"]


def test_offline_hold_is_key_specific_and_has_no_writer_approval(monkeypatch, tmp_path):
    class OfflineOnce(SignedPinServer):
        def __init__(self):
            super().__init__()
            self.remaining = 1

        def __call__(self, path, body, headers):
            if self.remaining:
                self.remaining -= 1
                raise TimeoutError("offline")
            return super().__call__(path, body, headers)

    server = OfflineOnce()
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    first = app._admin_pin_approval_for(
        "CA.TRAY_HOLD", "e" * 64, lambda: {"version": 1},
        ("original-label",), lambda _intent: False)
    assert first is None
    pending = app._admin_pin_store().pending("CA.TRAY_HOLD", "e" * 64)
    assert len(pending) == 1 and pending[0]["state"] == "UNVERIFIED_DETACHING"
    assert pending[0]["reason"] == "VERIFY_UNAVAILABLE"
    second = app._admin_pin_approval_for(
        "CA.TRAY_HOLD", "f" * 64, lambda: {"version": 1},
        ("other-label",), lambda _intent: False)
    assert second is not None and second["target"] == "f" * 64
    assert [event for event, _ in audits].count("ADMIN_PIN_UNVERIFIED_HOLD") == 0


@pytest.mark.parametrize("route", ("retry", "hold"))
@pytest.mark.parametrize("interrupted", (False, True))
def test_offline_stale_current_pin_hold_releases_other_phs2_and_keeps_key(
        monkeypatch, tmp_path, route, interrupted):
    from Container_Audit import ContainerAudit, TraySession, WarningPresenter, messagebox
    from storage_utils import atomic_write_json
    from tests.test_paired_preflight_handoff import _app

    app, hold_store, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations()
    stale = hold_store.path.parent / "current.json"
    atomic_write_json(stale, current)
    original = stale.read_bytes()
    quarantine = app._quarantine_current_tray_state
    app._quarantine_current_tray_state = lambda _reason: None
    app._load_current_tray_state()
    assert app._paired_stale_current_blocked
    app._quarantine_current_tray_state = quarantine
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app._admin_pin_approval_for = ContainerAudit._admin_pin_approval_for.__get__(app)
    app._admin_pin_client = make_client(
        monkeypatch, lambda *_args: (_ for _ in ()).throw(TimeoutError("offline")))
    app._prompt_blocked_work_admin_pin = lambda: ("manager-1", "194826")
    audits = []
    app._log_event = lambda event, **_kwargs: audits.append(event) or True
    app.warning_presenter = WarningPresenter()
    app._stop_warning_beep = lambda: None
    app.scanned_listbox = SimpleNamespace(delete=lambda *_args: None)
    app._reset_ui_to_waiting_state = lambda: None
    app._update_all_summaries = lambda: None
    app._render_warning_state = lambda: None
    monkeypatch.setattr(messagebox, "askyesno", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(messagebox, "showwarning", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(messagebox, "showerror", lambda *_args, **_kwargs: None)
    attempt = (app._retry_paired_stale_current_preservation if route == "retry"
               else app._continue_after_paired_stale_current)
    if interrupted:
        def crash_after_move(reason):
            result = quarantine(reason)
            raise KeyboardInterrupt("stopped after original move")
        app._quarantine_current_tray_state = crash_after_move
        with pytest.raises(KeyboardInterrupt):
            attempt()
        assert app._admin_pin_store().list_pending()[0]["state"] == "UNVERIFIED_DETACHING"
        assert "ADMIN_PIN_UNVERIFIED_HOLD" not in audits
        app._quarantine_current_tray_state = quarantine
        app._admin_pin_resume_unverified_detachments(startup=True)
    else:
        assert attempt() is False
    intent = app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "UNVERIFIED_OPERATOR_HOLD"
    assert audits.count("ADMIN_PIN_UNVERIFIED_HOLD") == 1
    assert not stale.exists()
    assert any(path.read_bytes() == original for path in stale.parent.glob("current.json.bad-*"))
    assert_other_phs2_starts(app, current["master_label_code"])
    app._recheck_admin_pin_intents()
    assert app._admin_pin_store().read(intent["operation_key"])["state"] == "HANDED_OFF_UNKNOWN"
    assert app._paired_preflight_blocks_label(current["master_label_code"])


def test_offline_stale_marker_identifies_two_keys_without_pin_effect(monkeypatch, tmp_path):
    from storage_utils import atomic_write_json

    app = offline_passive_app(monkeypatch, tmp_path)
    first = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-A|CLC=AAA2270730100|LBL=A|HSH=0123456789abcdef"
    second = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-B|CLC=AAA2270730100|LBL=B|HSH=0123456789abcdef"
    marker = app._paired_preflight_store().directory / ("stale-current-" + ("a" * 64) + ".json")
    atomic_write_json(marker, {"schema": "damaged", "labels": []})
    original = marker.read_bytes()
    source = {"marker_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
              "labels": [first, second], "state": {}}
    assert app._preflight_context_blocks_mutation()
    assert app._admin_pin_approval_for("CA.PAIR_RETRY", marker.stem, lambda: source,
                                       (first, second), lambda _intent: False) is None
    intent = app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "UNVERIFIED_OPERATOR_HOLD"
    assert marker.read_bytes() == original
    assert_other_phs2_starts(app, first)
    assert app._paired_preflight_blocks_label(second)


@pytest.mark.parametrize("action", ("CA.PAIR_RETRY", "CA.TRAY_HOLD"))
def test_offline_existing_pair_source_keeps_only_pair_keys(monkeypatch, tmp_path, action):
    from Container_Audit import ContainerAudit, messagebox
    from tests.test_paired_preflight_handoff import _app

    app, _hold, current = _app(tmp_path, monkeypatch)
    assert app._defer_paired_preflight_from_operations()
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app._admin_pin_approval_for = ContainerAudit._admin_pin_approval_for.__get__(app)
    app._admin_pin_client = make_client(
        monkeypatch, lambda *_args: (_ for _ in ()).throw(TimeoutError("offline")))
    app._prompt_blocked_work_admin_pin = lambda: ("manager-1", "194826")
    monkeypatch.setattr(messagebox, "askyesno", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(messagebox, "showerror", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(messagebox, "showwarning", lambda *_args, **_kwargs: None)
    record = app._paired_preflight_store().paths()[0]
    labels = tuple(app._paired_preflight_store().inspect(record).labels)
    if action == "CA.PAIR_RETRY":
        source = {"master_label_code": current["master_label_code"],
                  "current": dict(current), "state_sha256": pin.fingerprint(dict(current))}
        target = hashlib.sha256(current["master_label_code"].encode()).hexdigest()
    else:
        source = {"handoff_id": record.parent.name,
                  "record_sha256": hashlib.sha256(record.read_bytes()).hexdigest(),
                  "problems": []}
        target = record.parent.name
    assert app._admin_pin_approval_for(action, target, lambda: source,
                                       labels,
                                       lambda _intent: False) is None
    assert app._admin_pin_store().list_pending()[0]["state"] == "UNVERIFIED_OPERATOR_HOLD"
    assert_other_phs2_starts(app, current["master_label_code"])
    assert all(app._paired_preflight_blocks_label(label) for label in labels)


@pytest.mark.parametrize("action", ("CA.PAIR_HANDOFF", "CA.TRAY_HOLD"))
def test_offline_audit_source_binds_key_without_approval_effect(monkeypatch, tmp_path, action):
    app = offline_passive_app(monkeypatch, tmp_path)
    audit_file = Path(app.local_events_folder) / "audit.csv"
    audit_file.parent.mkdir(parents=True)
    def log_event(event, detail=None, **_kwargs):
        with audit_file.open("a", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=("event", "details"))
            if stream.tell() == 0:
                writer.writeheader()
            writer.writerow({"event": event, "details": json.dumps(detail or {})})
        return True
    app._log_event = log_event
    label = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-AUDIT|CLC=AAA2270730100|LBL=AUDIT|HSH=0123456789abcdef"
    other_bound = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-AUDIT2|CLC=AAA2270730100|LBL=AUDIT2|HSH=0123456789abcdef"
    labels = (label, other_bound) if action == "CA.PAIR_HANDOFF" else (label,)
    log_event("PHS2_PAIRED_RECOVERY_DEFERRED", {})
    row = next(row for row in app._parked_store().enumerate_key_evidence(
        pair_store=app._paired_preflight_store()) if row.kind == "audit")
    assert row.unidentified
    source = {"source_audit_id": row.evidence_id,
              "source_sha256": row.content_sha256, "labels": list(labels)}
    target = row.evidence_id
    assert app._admin_pin_approval_for(action, target, lambda: source,
                                       labels, lambda _intent: False) is None
    assert app._admin_pin_store().list_pending()[0]["state"] == "UNVERIFIED_OPERATOR_HOLD"
    assert_other_phs2_starts(app, label)
    assert all(app._paired_preflight_blocks_label(value) for value in labels)
    assert not app._paired_preflight_blocks_label(
        "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-FREE|CLC=AAA2270730100|LBL=FREE|HSH=0123456789abcdef")


def test_offline_damaged_parked_source_binds_only_selected_key(monkeypatch, tmp_path):
    app = offline_passive_app(monkeypatch, tmp_path)
    label = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-PARKED|CLC=AAA2270730100|LBL=PARKED|HSH=0123456789abcdef"
    path = Path(app.parked_trays_dir) / "parked_damaged.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{damaged")
    original = path.read_bytes()
    source = {"source_file": path.name, "source_sha256": hashlib.sha256(original).hexdigest(),
              "label": label}
    assert app._admin_pin_approval_for("CA.TRAY_HOLD", "parked-target", lambda: source,
                                       (label,), lambda _intent: False) is None
    assert app._admin_pin_store().list_pending()[0]["state"] == "UNVERIFIED_OPERATOR_HOLD"
    assert path.read_bytes() == original
    assert_other_phs2_starts(app, label)


@pytest.mark.parametrize("boundary", ("before_hold", "after_hold", "after_current", "after_release"))
def test_paired_handoff_resumes_same_consumed_key_across_writer_boundaries(
        monkeypatch, tmp_path, boundary):
    from Container_Audit import ContainerAudit, messagebox
    from paired_preflight_handoff import PairedPreflightHandoffStore
    from tests.test_paired_preflight_handoff import _app

    app, _hold_store, _current = _app(tmp_path, monkeypatch)
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app.local_events_folder = str(tmp_path / "local-events")
    def log_event(event, detail=None, **_kwargs):
        path = Path(app.local_events_folder) / "pin-boundary.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=("event", "details"))
            if stream.tell() == 0:
                writer.writeheader()
            writer.writerow({"event": event, "details": json.dumps(detail or {})})
        return True
    app._log_event = log_event
    server = SignedPinServer()
    app._admin_pin_client = make_client(monkeypatch, server)
    app._prompt_blocked_work_admin_pin = lambda: ("manager-1", "194826")
    app._admin_pin_approval_for = ContainerAudit._admin_pin_approval_for.__get__(app)
    app._admin_pin_complete = ContainerAudit._admin_pin_complete.__get__(app)
    monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: None)
    monkeypatch.setattr(messagebox, "showwarning", lambda *args, **kwargs: None)
    monkeypatch.setattr(messagebox, "showinfo", lambda *args, **kwargs: None)

    original_move = PairedPreflightHandoffStore.move_original
    original_release = PairedPreflightHandoffStore.release
    interrupted = {"done": False}

    def move(self, path, name):
        if not interrupted["done"] and boundary == "before_hold" and name == "hold":
            interrupted["done"] = True
            raise OSError("interrupted before first original move")
        original_move(self, path, name)
        if (not interrupted["done"] and
                ((boundary == "after_hold" and name == "hold") or
                 (boundary == "after_current" and name == "current"))):
            interrupted["done"] = True
            raise OSError("interrupted after original move")

    def release(self, path):
        original_release(self, path)
        if not interrupted["done"] and boundary == "after_release":
            interrupted["done"] = True
            raise OSError("interrupted after release marker")

    monkeypatch.setattr(PairedPreflightHandoffStore, "move_original", move)
    monkeypatch.setattr(PairedPreflightHandoffStore, "release", release)
    assert app._defer_paired_preflight_from_operations() is False
    assert interrupted["done"]
    intent = app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "CONSUMED"
    assert len([path for path, _ in server.calls if path.endswith("/redemptions")]) == 1
    if boundary == "after_release":
        app._recheck_admin_pin_intents()
    else:
        assert app._defer_paired_preflight_from_operations() is True
    assert app._admin_pin_store().read(intent["operation_key"])["state"] == "APPLIED"
    assert len([path for path, _ in server.calls if path.endswith("/redemptions")]) == 1


def test_offline_pair_hold_detaches_active_originals_and_other_item_starts(monkeypatch, tmp_path):
    from Container_Audit import ContainerAudit, TraySession, messagebox
    from tests.test_paired_preflight_handoff import _app

    app, hold_store, current = _app(tmp_path, monkeypatch)
    app._admin_pin_login_epoch = uuid.uuid4().hex
    def offline(_path, _body, _headers):
        raise TimeoutError("offline")
    app._admin_pin_client = make_client(monkeypatch, offline)
    app._prompt_blocked_work_admin_pin = lambda: ("manager-1", "194826")
    app._admin_pin_approval_for = ContainerAudit._admin_pin_approval_for.__get__(app)
    app._admin_pin_complete = ContainerAudit._admin_pin_complete.__get__(app)
    monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: None)
    monkeypatch.setattr(messagebox, "showwarning", lambda *args, **kwargs: None)
    assert app._defer_paired_preflight_from_operations() is False
    pending = app._admin_pin_store().list_pending()
    assert len(pending) == 1 and pending[0]["state"] == "UNVERIFIED_OPERATOR_HOLD"
    assert not hold_store.path.exists()
    assert not (Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).exists()
    assert not app._preflight_context_blocks_mutation()
    assert not app._warning_state_presenter().state.is_blocking
    assert not app._scan_entry_admission_block_reason()
    assert app._paired_preflight_blocks_label(current["master_label_code"])
    app.current_tray = TraySession()
    app.is_idle = False
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app._intercept_phs_reconciliation_scan = lambda _value: False
    app._intercept_active_tray_phs2_scan = lambda _value: False
    app._is_completed_master_label = lambda _value: False
    app._item_catalog = lambda: SimpleNamespace(
        find_by_code=lambda _code: {"Item Code": "AAA2270730100"})
    app.show_fullscreen_warning = lambda *_args: None
    started = []
    app._begin_compact_phs2_preflight = lambda **kwargs: started.append(kwargs["barcode"])
    other = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-FREE|CLC=AAA2270730100|LBL=FREE|HSH=0123456789abcdef"
    app._process_barcode_logic(current["master_label_code"])
    app._process_barcode_logic(other)
    assert started == [other]


def test_offline_precheck_hold_preserves_bytes_and_releases_busy_slot(monkeypatch, tmp_path):
    from Container_Audit import ContainerAudit, messagebox
    from tests.test_container_p0_contracts import _preflight_hold_ownership_app

    _module, app, hold = _preflight_hold_ownership_app(tmp_path, monkeypatch)
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    label = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-HOLD|CLC=AAA2270730100|LBL=HOLD|HSH=0123456789abcdef"
    hold.start(worker="tester", master_raw=label, scan_epoch=1)
    hold.append("PRODUCT-A")
    hold.mark_failed(error_code="PHS2_PREFLIGHT_UNAVAILABLE")
    original = hold.path.read_bytes()
    def offline(_path, _body, _headers):
        raise TimeoutError("offline")
    app._admin_pin_client = make_client(monkeypatch, offline)
    app._prompt_blocked_work_admin_pin = lambda: ("manager-1", "194826")
    app._admin_pin_approval_for = ContainerAudit._admin_pin_approval_for.__get__(app)
    monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(messagebox, "showwarning", lambda *args, **kwargs: None)
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: None)
    assert app._quarantine_preflight_hold_for_supervisor(
        reason="supervisor_new_work_required", confirm=False) is False
    assert not hold.path.exists()
    assert any(path.read_bytes() == original for path in app._preflight_hold_quarantine_directory().glob("*.json"))
    assert not app._preflight_context_blocks_mutation()
    assert app._paired_preflight_blocks_label(label)
    assert app._admin_pin_store().list_pending()[0]["state"] == "UNVERIFIED_OPERATOR_HOLD"
    assert_other_phs2_starts(app, label)


def test_offline_tray_hold_preserves_snapshot_and_clears_active_session(monkeypatch, tmp_path):
    from Container_Audit import TraySession
    from storage_utils import atomic_write_json
    from tests.test_container_p0_contracts import _saved_tray_state
    from label_qr import canonical_master_label_key

    app, audits, _notices = make_headless_app(
        monkeypatch, tmp_path, lambda *_args: (_ for _ in ()).throw(TimeoutError("offline")))
    app.save_folder = str(tmp_path / "events")
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.PREFLIGHT_SCAN_HOLD_FILE = "hold.json"
    app.TRAY_SIZE = 60
    app.computer_id = "test-host"
    state = _saved_tray_state()
    app.current_tray = TraySession(master_label_code=state["master_label_code"])
    current = Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE
    atomic_write_json(current, state)
    presenter = SimpleNamespace(state=SimpleNamespace(completion=None, is_blocking=True))
    def clear_completion():
        presenter.state.is_blocking = False
    presenter.clear_completion = clear_completion
    presenter.acknowledge = lambda: None
    app._warning_state_presenter = lambda: presenter
    app._stop_warning_beep = lambda: None
    app._invalidate_pending_scan_callbacks = lambda: None
    app.scanned_listbox = SimpleNamespace(delete=lambda *_args: None)
    app._reset_ui_to_waiting_state = lambda: None
    app._update_all_summaries = lambda: None
    app._update_parked_trays_list = lambda: None
    app._render_warning_state = lambda: None
    app._update_action_button_states = lambda: None
    label = state["master_label_code"]
    target_id = hashlib.sha256(canonical_master_label_key(label).encode()).hexdigest()
    source = lambda: {"tray": state, "current_sha256": hashlib.sha256(current.read_bytes()).hexdigest()}
    assert app._admin_pin_approval_for("CA.TRAY_HOLD", target_id, source,
                                       (label,), lambda _intent: False) is None
    assert not current.exists()
    parked = app._parked_store().existing_label_path_any_worker(master_label=label)
    assert parked is not None and app._parked_store().load(parked) == state
    assert not app.current_tray.master_label_code
    assert not app._preflight_context_blocks_mutation()
    assert not app._scan_entry_admission_block_reason()
    assert app._paired_preflight_blocks_label(label)
    assert [event for event, _ in audits] == ["ADMIN_PIN_UNVERIFIED", "ADMIN_PIN_UNVERIFIED_HOLD"]
    assert_other_phs2_starts(app, label)


def test_consumed_precheck_quarantine_resumes_after_restart_epoch(monkeypatch, tmp_path):
    from Container_Audit import ContainerAudit, messagebox
    from preflight_scan_hold import PreflightScanHoldStore
    from tests.test_container_p0_contracts import _preflight_hold_ownership_app

    _module, app, hold = _preflight_hold_ownership_app(tmp_path, monkeypatch)
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.local_events_folder = str(tmp_path / "local-events")
    def log_event(event, detail=None, **_kwargs):
        path = Path(app.local_events_folder) / "precheck-resume.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=("event", "details"))
            if stream.tell() == 0:
                writer.writeheader()
            writer.writerow({"event": event, "details": json.dumps(detail or {})})
        return True
    app._log_event = log_event
    hold.start(worker="tester", master_raw="MASTER", scan_epoch=1)
    hold.append("PRODUCT-A")
    hold.mark_failed(error_code="PHS2_PREFLIGHT_UNAVAILABLE")
    original = hold.path.read_bytes()
    server = SignedPinServer()
    app._admin_pin_client = make_client(monkeypatch, server)
    app._prompt_blocked_work_admin_pin = lambda: ("manager-1", "194826")
    app._admin_pin_approval_for = ContainerAudit._admin_pin_approval_for.__get__(app)
    app._admin_pin_complete = ContainerAudit._admin_pin_complete.__get__(app)
    monkeypatch.setattr(messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(messagebox, "showinfo", lambda *args, **kwargs: None)
    monkeypatch.setattr(messagebox, "showwarning", lambda *args, **kwargs: None)
    monkeypatch.setattr(messagebox, "showerror", lambda *args, **kwargs: None)
    original_quarantine = PreflightScanHoldStore.quarantine
    interrupted = {"once": False}
    def crash_after_move(self, *args, **kwargs):
        result = original_quarantine(self, *args, **kwargs)
        if not interrupted["once"]:
            interrupted["once"] = True
            raise KeyboardInterrupt("simulated stop after durable move")
        return result
    monkeypatch.setattr(PreflightScanHoldStore, "quarantine", crash_after_move)
    with pytest.raises(KeyboardInterrupt):
        app._quarantine_preflight_hold_for_supervisor(
            reason="supervisor_new_work_required", confirm=False)
    intent = app._admin_pin_store().list_pending()[0]
    assert intent["state"] == "CONSUMED" and not hold.path.exists()
    assert any(path.read_bytes() == original for path in app._preflight_hold_quarantine_directory().glob("*.json"))
    app.worker_name = "worker-2"
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app._recheck_admin_pin_intents()
    assert app._admin_pin_store().read(intent["operation_key"])["state"] == "APPLIED"
    assert app._admin_pin_store().read(intent["operation_key"])["resuming_operator"]["local_id"] == "worker-2"
    assert len([path for path, _ in server.calls if path.endswith("/redemptions")]) == 1


def test_stale_recheck_recovery_reads_marker_with_json_suffix(monkeypatch, tmp_path):
    from storage_utils import atomic_write_json

    app, _audits, _notices = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    app.save_folder = str(tmp_path / "events")
    app.local_events_folder = str(tmp_path / "local-events")
    original_hash = "a" * 64
    marker = app._paired_preflight_store().directory / f"stale-current-{original_hash}.json"
    atomic_write_json(marker, {
        "schema": "container-audit-stale-current-hold-v1", "labels": ["MASTER"],
        "original_sha256": original_hash, "changed_sha256": "b" * 64,
    })
    key = str(uuid.uuid4())
    audit = Path(app.local_events_folder) / "audit.csv"
    audit.parent.mkdir(parents=True, exist_ok=True)
    with audit.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("event", "details"))
        writer.writeheader()
        writer.writerow({"event": "PHS2_STALE_HOLD_RECHECKED",
                         "details": json.dumps({"operation_key": key})})
    intent = {"action": "CA.PAIR_RETRY", "operation_key": key,
              "target": {"id": marker.stem},
              "source_snapshot": {"marker_sha256": hashlib.sha256(marker.read_bytes()).hexdigest()}}
    assert app._admin_pin_recovered_effect(intent)
    assert not app._admin_pin_target_missing(intent)

"""Changed quarantine bytes require an independent, newly consumed approval."""
import json
import uuid
from pathlib import Path

import pytest

from container_admin_pin import AdminPinError
from pin_file_move import file_sha256
from tests.test_admin_pin_move_timing import _business_case


def _changed_restore(monkeypatch, tmp_path):
    app, server, audits, original, label, invoke = _business_case(
        monkeypatch, tmp_path, "CA.PRECHECK_HOLD")
    assert invoke() is True
    store = app._admin_pin_store()
    quarantine = next(row for row in store.list_pending() if row["state"] == "APPLIED")
    held = Path(quarantine["moving"][0]["target"])
    initial = held.read_bytes()
    client = app._admin_pin_client
    client._test_c12_server = server
    rename = Path.rename

    def change_after_redeem(source, target):
        if source != held:
            return rename(source, target)
        payload = json.loads(held.read_text(encoding="utf-8"))
        payload["error_code"] = "C12_CHANGED"
        held.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return rename(source, target)

    monkeypatch.setattr(Path, "rename", change_after_redeem)
    restore = lambda: app.restore_quarantined_preflight_hold(str(held), _confirmed=True)
    assert restore() is False
    monkeypatch.setattr(Path, "rename", rename)
    changed = next(row for row in store.list_pending() if row["state"] == "TARGET_CHANGED")
    assert initial != held.read_bytes() and not original.exists()
    return app, client, audits, store, quarantine, changed, held, original, label, restore


def _reapproval_case(monkeypatch, tmp_path, boundary):
    (app, client, audits, store, quarantine, changed, held,
     original, label, restore) = _changed_restore(monkeypatch, tmp_path)
    before = held.read_bytes()
    prompt = app._prompt_blocked_work_admin_pin
    prompts = []

    def count_prompt(**kwargs):
        prompts.append(kwargs)
        return prompt(**kwargs)

    monkeypatch.setattr(app, "_prompt_blocked_work_admin_pin", count_prompt)
    if boundary == "cancel":
        monkeypatch.setattr(app, "_prompt_blocked_work_admin_pin",
                            lambda **kwargs: prompts.append(kwargs))
        assert restore() is False
        assert prompts and held.read_bytes() == before and not original.exists()
        monkeypatch.setattr(app, "_prompt_blocked_work_admin_pin", count_prompt)
    elif boundary in {"invalid", "timeout"}:
        monkeypatch.setattr("Container_Audit.messagebox.askyesno", lambda *args, **kwargs: False)
        verify = client.verify
        def unavailable(**kwargs):
            raise AdminPinError("PIN_INVALID" if boundary == "invalid" else "VERIFY_UNAVAILABLE",
                                unknown=boundary == "timeout")
        monkeypatch.setattr(client, "verify", unavailable)
        assert restore() is False
        assert prompts and held.read_bytes() == before and not original.exists()
        assert app._paired_preflight_blocks_label(label)
        monkeypatch.setattr(client, "verify", verify)
    elif boundary == "restart":
        app._admin_pin_login_epoch = uuid.uuid4().hex
        app._preflight_hold_store_instance = None
        app._preflight_hold_snapshot = None
    elif boundary == "changed_again":
        redeem = client.redeem
        def change_again(**kwargs):
            result = redeem(**kwargs)
            held.write_bytes(held.read_bytes() + b"\n")
            return result
        monkeypatch.setattr(client, "redeem", change_again)
        assert restore() is False
        assert prompts and not original.exists() and held.exists()
        monkeypatch.setattr(client, "redeem", redeem)
        before = held.read_bytes()
    assert restore() is True
    assert prompts and not held.exists() and original.read_bytes() == before
    assert not app._paired_preflight_blocks_label(label)
    saved = store.read(quarantine["operation_key"])
    assert saved["restoration"]["state"] == "RESTORED"
    assert saved["source_snapshot"] == quarantine["source_snapshot"]
    assert store.read(changed["operation_key"])["state"] == "SUPERSEDED"
    assert "PHS2_PREFLIGHT_HOLD_RESTORED" in audits
    applied = [row for row in store.list_pending()
               if row["state"] == "APPLIED" and row["source_snapshot"].get("restore_preflight_id")]
    assert len(applied) == 1
    assert applied[0]["operation_key"] != changed["operation_key"]
    assert applied[0]["source_snapshot"]["hold_sha256"] == file_sha256(original)


def test_c12_fresh_approval(monkeypatch, tmp_path):
    _reapproval_case(monkeypatch, tmp_path, "normal")


def test_c12_cancel_does_not_restore(monkeypatch, tmp_path):
    _reapproval_case(monkeypatch, tmp_path, "cancel")


def test_c12_invalid_pin_does_not_restore(monkeypatch, tmp_path):
    _reapproval_case(monkeypatch, tmp_path, "invalid")


def test_c12_timeout_keeps_quarantine(monkeypatch, tmp_path):
    _reapproval_case(monkeypatch, tmp_path, "timeout")


def test_c12_restart_keeps_quarantine(monkeypatch, tmp_path):
    _reapproval_case(monkeypatch, tmp_path, "restart")


def test_c12_second_change_requires_another_approval(monkeypatch, tmp_path):
    _reapproval_case(monkeypatch, tmp_path, "changed_again")


def test_c12_reapproval_preserves_other_hold_and_approval(monkeypatch, tmp_path):
    from preflight_scan_hold import PreflightScanHoldStore

    (app, client, audits, store, quarantine, changed, held,
     original, label, restore) = _changed_restore(monkeypatch, tmp_path)
    other = PreflightScanHoldStore(Path(app.save_folder) / "unrelated_hold.json", capacity=8)
    other.start(worker="unrelated-worker", master_raw="unrelated-label", scan_epoch=17)
    other.append("unrelated-member")
    other_intent = store.write(dict(changed, operation_key=str(uuid.uuid4()),
                                    target=dict(changed["target"], id="unrelated-target"),
                                    labels=["unrelated-label"]))
    other_path = store.path(other_intent["operation_key"])
    before = (other.path.read_bytes(), other_path.read_bytes())
    selected = PreflightScanHoldStore.load_path(held)
    assert restore() is True
    assert before == (other.path.read_bytes(), other_path.read_bytes())
    restored = PreflightScanHoldStore.load_path(original)
    assert (restored.worker, restored.master_raw, restored.items) == (
        selected.worker, selected.master_raw, selected.items)
    assert app._paired_preflight_blocks_label("unrelated-label")
    assert not app._paired_preflight_blocks_label(label)


def test_c12_restart_before_redeem_requests_new_approval(monkeypatch, tmp_path):
    (app, client, audits, store, quarantine, changed, held,
     original, label, restore) = _changed_restore(monkeypatch, tmp_path)
    before = held.read_bytes()
    client._test_c12_server.consumed = False
    redeem = client.redeem
    def stopped(**kwargs):
        raise KeyboardInterrupt("before redemption")
    monkeypatch.setattr(client, "redeem", stopped)
    with pytest.raises(KeyboardInterrupt):
        restore()
    prepared = next(row for row in store.list_pending() if row["state"] == "VERIFIED")
    assert held.read_bytes() == before and not original.exists()
    app._admin_pin_login_epoch = uuid.uuid4().hex
    app._preflight_hold_store_instance = None
    app._preflight_hold_snapshot = None
    monkeypatch.setattr(client, "redeem", redeem)
    assert restore() is True
    assert store.read(prepared["operation_key"])["state"] == "SUPERSEDED"
    fresh = next(row for row in store.list_pending() if row["state"] == "APPLIED"
                 and row["source_snapshot"].get("restore_preflight_id"))
    assert fresh["request_id"] != prepared["request_id"]
    assert fresh["operation_key"] != prepared["operation_key"]
    assert original.read_bytes() == before

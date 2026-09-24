"""A PIN authorizes the bytes at the final file move, including after restart."""

from __future__ import annotations

import hashlib
import sys
import uuid
from pathlib import Path

import pytest

from Container_Audit import ContainerAudit
from event_stream_policy import local_only_event_log_path
from pin_file_move import PinnedTargetChanged, file_sha256, locked_pinned_source
from tests.test_container_admin_pin import SignedPinServer, make_headless_app


ACTIONS = (
    ("CA.PRECHECK_HOLD", "hold.json", "hold.quarantine.json"),
    ("CA.PAIR_RETRY", "current.json", "current.bad-1"),
    ("CA.PAIR_HANDOFF", "paired-current.json", "current.original"),
    ("CA.TRAY_HOLD", "tray.json", "tray.bad-1"),
)


def _approval(app, action, original, target_id):
    return app._admin_pin_approval_for(
        action, target_id, lambda: {"source_sha256": file_sha256(original)},
        ("PHS2-original",), lambda _intent: False,
    )


@pytest.mark.parametrize("action,source_name,held_name", ACTIONS)
@pytest.mark.parametrize("timing", ("redemption", "after_audit", "before_move"))
def test_changed_bytes_need_new_pin_at_each_boundary(
        monkeypatch, tmp_path, action, source_name, held_name, timing):
    original, held = tmp_path / source_name, tmp_path / held_name
    original.write_bytes(b"original bytes")
    changed = b"changed bytes for the same key"
    server = SignedPinServer()
    changed_at_redeem = {"done": False}

    def transport(path, body, headers):
        reply = server(path, body, headers)
        if (timing == "redemption" and path.endswith("/redemptions")
                and not changed_at_redeem["done"]):
            changed_at_redeem["done"] = True
            original.write_bytes(changed)
        return reply

    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, transport)
    target_id = hashlib.sha256(action.encode()).hexdigest()
    approval = _approval(app, action, original, target_id)
    if timing == "redemption":
        assert approval is None
    else:
        assert approval is not None
        if timing == "after_audit":
            assert app._log_event("PHS2_TEST_EFFECT_AUDIT", detail={"operation_key": approval["operation_key"]})
            original.write_bytes(changed)
        else:
            real_rename = Path.rename

            def change_at_move(path, target):
                if path == original:
                    original.write_bytes(changed)
                return real_rename(path, target)

            monkeypatch.setattr(Path, "rename", change_at_move)
        with pytest.raises(PinnedTargetChanged):
            app._admin_pin_move(approval, original, held, hashlib.sha256(b"original bytes").hexdigest())
        if timing == "before_move":
            monkeypatch.setattr(Path, "rename", real_rename)
    old = app._admin_pin_store().pending(action, target_id)[0]
    assert old["state"] == "TARGET_CHANGED"
    assert original.read_bytes() == changed
    assert not held.exists()
    assert all(event != "ADMIN_PIN_APPLIED" for event, _ in audits)

    app._recheck_admin_pin_intents()
    other = tmp_path / "another-key.json"
    other_held = tmp_path / "another-key.held"
    other.write_bytes(b"other key")
    other_key = _approval(app, action, other, "f" * 64)
    assert other_key is not None
    app._admin_pin_move(other_key, other, other_held, file_sha256(other))
    assert app._admin_pin_complete(other_key, lambda _intent: other_held.read_bytes() == b"other key")

    fresh = _approval(app, action, original, target_id)
    assert fresh is not None and fresh["operation_key"] != old["operation_key"]
    app._admin_pin_move(fresh, original, held, hashlib.sha256(changed).hexdigest())
    assert app._admin_pin_complete(fresh, lambda _intent: held.read_bytes() == changed)
    assert app._admin_pin_store().read(old["operation_key"])["state"] == "SUPERSEDED"
    assert app._admin_pin_store().read(fresh["operation_key"])["state"] == "APPLIED"
    assert held.read_bytes() == changed


@pytest.mark.skipif(sys.platform != "win32", reason="Windows share mode is the production lock")
def test_audit_source_lock_blocks_mutation_until_effect_readback(monkeypatch, tmp_path):
    source = tmp_path / "damaged-parked.json"
    source.write_bytes(b"pinned evidence")
    app, _audits, _notices = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    approval = _approval(app, "CA.TRAY_HOLD", source, "d" * 64)
    assert approval is not None
    with app._admin_pin_locked_sources(approval, [(source, file_sha256(source))]):
        with pytest.raises(OSError):
            source.write_bytes(b"changed while audit writes")
        assert source.read_bytes() == b"pinned evidence"
    source.write_bytes(b"changed after release")
    assert source.read_bytes() == b"changed after release"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows share mode is the production lock")
@pytest.mark.parametrize("action,source_name,held_name", ACTIONS)
def test_success_audit_keeps_moved_bytes_locked(monkeypatch, tmp_path,
                                               action, source_name, held_name):
    original, held = tmp_path / source_name, tmp_path / held_name
    original.write_bytes(b"exactly pinned")
    app, audits, _notices = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    approval = _approval(app, action, original, hashlib.sha256(action.encode()).hexdigest())
    assert approval is not None
    app._admin_pin_move(approval, original, held, hashlib.sha256(b"exactly pinned").hexdigest())
    real_log = app._log_event
    blocked = []

    def audit_with_mutation(event, **kwargs):
        if event == "ADMIN_PIN_APPLIED":
            with pytest.raises(OSError):
                held.write_bytes(b"late change")
            blocked.append(True)
        return real_log(event, **kwargs)

    app._log_event = audit_with_mutation
    assert app._admin_pin_complete(approval, lambda _intent: held.read_bytes() == b"exactly pinned")
    assert blocked == [True]
    assert held.read_bytes() == b"exactly pinned"
    assert [event for event, _ in audits].count("ADMIN_PIN_APPLIED") == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows share mode is the production lock")
def test_audit_evidence_success_uses_separate_local_stream(monkeypatch, tmp_path):
    app, _audits, _notices = make_headless_app(monkeypatch, tmp_path, SignedPinServer())
    app.save_folder = str(tmp_path / "events")
    app.local_events_folder = str(tmp_path / "local_events")
    source = tmp_path / "local_events" / "source.csv"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"existing audit evidence")
    destinations = []

    def write_audit(_event, **kwargs):
        override = kwargs.get("log_file_path_override")
        destination = (local_only_event_log_path(
            override, local_events_dir=app.local_events_folder) if override else source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("ab") as stream:
            stream.write(b"new audit\n")
        destinations.append(destination)
        return True

    app._log_event = write_audit
    intent = {"operation_key": str(uuid.uuid4()), "action": "CA.PAIR_HANDOFF",
              "target": {"id": "e" * 64}, "operator": {"local_id": "worker-1"},
              "source_snapshot": {"source_audit_id": "source-row"}}
    with locked_pinned_source(source, file_sha256(source)):
        assert app._admin_pin_audit("ADMIN_PIN_APPLIED", intent)
    assert destinations[0] != source
    assert source.read_bytes() == b"existing audit evidence"


@pytest.mark.parametrize("action,source_name,held_name", ACTIONS)
@pytest.mark.parametrize("boundary", ("after_move", "after_verification", "after_readback"))
@pytest.mark.parametrize("changed", (False, True))
def test_move_journal_recovers_each_interruption(
        monkeypatch, tmp_path, action, source_name, held_name, boundary, changed):
    original, held = tmp_path / source_name, tmp_path / held_name
    raw = b"pinned original bytes"
    original.write_bytes(raw)
    server = SignedPinServer()
    app, _audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    approval = _approval(app, action, original, hashlib.sha256(action.encode()).hexdigest())
    assert approval is not None
    expected = hashlib.sha256(raw).hexdigest()
    if boundary == "after_move":
        real_rename = Path.rename

        def interrupt_after_rename(path, target):
            result = real_rename(path, target)
            if path == original:
                raise KeyboardInterrupt("after atomic move")
            return result

        monkeypatch.setattr(Path, "rename", interrupt_after_rename)
        with pytest.raises(KeyboardInterrupt):
            app._admin_pin_move(approval, original, held, expected)
        monkeypatch.setattr(Path, "rename", real_rename)
    else:
        app._admin_pin_move(approval, original, held, expected)
        if boundary == "after_readback":
            assert held.read_bytes() == raw and not original.exists()
    intent = app._admin_pin_store().read(approval["operation_key"])
    assert intent["move_state"] == "MOVING" and intent["moving"][0]["sha256"] == expected
    if changed:
        held.write_bytes(b"changed while interrupted")
    restarted, audits, _notices = make_headless_app(monkeypatch, tmp_path, server)
    current = restarted._admin_pin_store().read(approval["operation_key"])
    if changed:
        assert not restarted._admin_pin_check_moves(current)
        assert original.read_bytes() == b"changed while interrupted"
        assert not held.exists()
        assert restarted._admin_pin_store().read(approval["operation_key"])["state"] == "TARGET_CHANGED"
        assert all(event != "ADMIN_PIN_APPLIED" for event, _ in audits)
    else:
        assert restarted._admin_pin_check_moves(current)
        assert restarted._admin_pin_complete(
            approval, lambda _intent: held.read_bytes() == raw and not original.exists())
        assert restarted._admin_pin_store().read(approval["operation_key"])["state"] == "APPLIED"
        assert [event for event, _ in audits].count("ADMIN_PIN_APPLIED") == 1

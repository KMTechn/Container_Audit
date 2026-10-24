"""Opt-in retained X -> compatible Y process chain, ANSWER-7/8."""
import json
import os
from pathlib import Path
import time

import pytest

from tests import _update_host as host


def _read(path):
    return json.loads(path.read_bytes())


def _events(root):
    result = []
    for path in (root / "observations").glob("*.jsonl"):
        with path.open(encoding="utf-8") as stream:
            result.extend(json.loads(line) for line in stream)
    return result


def test_retained_timeout_x_then_compatible_y_confirmed(tmp_path):
    packet = os.environ.get("CONTAINER_AUDIT_HOST_TEST_PACKET")
    if not packet:
        pytest.skip("attested release packet required")
    from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair
    import user_relay

    with P256KeyPair.generate() as signer:
        config = host.prepare(tmp_path, Path(__file__).resolve().parents[1],
                              Path(packet), signer, departure=host.departure_identity())
        root = config.parent
        value = _read(config)
        control = Path(value["control"])
        marker = root / "withhold-trial-ready"
        assert not marker.exists()
        x = host.prepare_update(config, signer)
        try:
            host.ready(config)
            marker.write_text(x, encoding="ascii")
            (root / "offer-ready").touch()
            host.wait_for(config, lambda: (root / "stage/prepared.json").exists(), seconds=600)
            host.session_end(config)
            bootstrap_rc = host.autorun(config)
            state_x = _read(control / "transition.json")
            assert state_x["phase"] == "DEFERRED"
            assert state_x.get("retained_candidate") is True
            assert state_x["failure_decision"]["selected_sha"] == x
            assert state_x["failure_decision"]["code"] in {
                "TRIAL_GENERATION_ADVANCED", "TRIAL_GENERATION_UNKNOWN"}
            assert _read(control / "active.json")["sha"] == x
            assert x in state_x["failed_shas"]
            assert not state_x.get("recovery_pending")
            assert "rollback_at" not in state_x
            assert "confirmed_at" not in state_x
            assert any(e["kind"] == "gui_ready_withheld" and e.get("candidate_sha") == x
                       for e in _events(root))
            assert marker.resolve().is_relative_to(root.resolve())
            marker.resolve().unlink()

            direct = Path(_read(root / "initial-ready-proof.json")["direct_sync_root"])
            status_path = user_relay.user_relay_status_path(direct)

            def relay_x_running():
                if not status_path.exists():
                    return False
                status = _read(status_path)
                return (status.get("status") == "RUNNING"
                        and status.get("source_commit") == x
                        and status.get("ordinary_user") is True
                        and not status.get("update_nonce"))

            host.wait_for(config, relay_x_running, seconds=180)
            normal_started = time.monotonic()
            gui = host.launch(config, str(root / "machine/versions" / x / "app/main.py"))

            def gui_x_ready():
                return [e for e in _events(root) if e.get("pid") == gui.pid
                        and e["kind"] in {"gui_existing_onboarding_state", "gui_onboarded"}
                        and e.get("status") == "READY"]

            host.wait_for(config, gui_x_ready, seconds=180)
            ready_event = min(gui_x_ready(), key=lambda e: e["at"])
            assert not any(e["kind"] == "gui_gate_returned" and e.get("pid") == gui.pid
                           for e in _events(root))
            assert _read(control / "transition.json") == state_x
            normal = {
                "gui_pid": gui.pid, "gui_adapter_ready": True,
                "ready_seconds_from_launch": ready_event["at"] - normal_started,
                "new_bootstrap_requested_by_active_gui": False,
                "recovery_marks": False, "rollback_attempted": False,
                "relay_running": relay_x_running(), "phase": state_x["phase"],
                "toolkit_rendering_executed": False}
            host.write(root / "retained-x-normal-start.json", normal)

            y = host.prepare_followup_update(config, signer)
            assert y != x
            compatible = _read(root / "followup-compatible-proof.json")
            assert compatible["signature_verified"] is True
            assert compatible["from_commit"] == x

            def prepared_y():
                path = root / "stage/prepared.json"
                return path.exists() and _read(path).get("source_commit") == y

            host.wait_for(config, prepared_y, seconds=600)
            # Close only this adapter GUI, then use the unchanged, birth-bound
            # owned logoff protocol for its ordinary relay. No app-stop marker.
            finish = root / "host-finish"
            assert not finish.exists()
            finish.touch()
            assert gui.wait(timeout=180) == 0
            host.session_end(config)
            assert finish.resolve().is_relative_to(root.resolve())
            finish.resolve().unlink()
            y_bootstrap_rc = host.autorun(config)
            result = host.read_result(config, y, y_bootstrap_rc)
            assert result["confirmed"]
            state_y = _read(control / "transition.json")
            assert state_y["previous_sha"] == x
            assert state_y["rollback_pair"]["to_commit"] == x
            assert _read(control / "active.json")["sha"] == y
            assert x in state_y["failed_shas"]
            assert state_y.get("policy_audit_applied") is True
            ordinary = host.launch(config, "ordinary-probe")
            ordinary_rc = ordinary.wait()
            result["ordinary_process_rc"] = ordinary_rc
            result["ordinary"] = _read(root / "ordinary-result.json")
            assert ordinary_rc == 0
            assert result["ordinary"]["status"] == "READY"
            host.write(root / "chain-result.json", result)
            host.write(root / "retained-chain-result.json", {
                "x": x, "y": y, "x_phase": state_x["phase"],
                "x_failure_code": state_x["failure_decision"]["code"],
                "x_failed_marker_present": x in state_x["failed_shas"],
                "x_normal_start": normal, "y_phase": state_y["phase"],
                "y_confirmed": result["confirmed"], "y_previous_sha": state_y["previous_sha"],
                "y_rollback_to": state_y["rollback_pair"]["to_commit"],
                "signed_compatibility_floor": compatible["data_compatible_min_version"],
                "compatibility_signature_verified": True,
                "x_bootstrap_rc": bootstrap_rc, "y_bootstrap_rc": y_bootstrap_rc,
                "ready_hold_marker_removed": not marker.exists(),
                "extra_manual_relay_start": False})
        finally:
            host.stop_owned_relays(config)

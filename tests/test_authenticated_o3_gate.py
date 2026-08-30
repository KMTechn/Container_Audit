from __future__ import annotations

import io
import json
import secrets
from pathlib import Path

import pytest

from tools import authenticated_o3_gate as gate


def _credential_payload() -> tuple[bytes, dict[str, dict[str, str]]]:
    origins: dict[str, dict[str, str]] = {}
    for profile in gate.PROFILES:
        origins[profile] = {
            "active_access_code": f"active-{profile}-{secrets.token_hex(12)}",
            "known_invalid_access_code": f"invalid-{profile}-{secrets.token_hex(12)}",
            "expired_session_cookie": f"session=expired-{profile}-{secrets.token_hex(12)}",
        }
    payload = {"schema": gate.CREDENTIAL_SCHEMA, "origins": origins}
    return json.dumps(payload).encode("utf-8"), origins


def _binding(tmp_path: Path) -> gate.Binding:
    origins = {
        profile: gate.OriginBinding(
            profile=profile,
            port=port,
            database=tmp_path / f"{profile}.db",
            login_mode="standard",
        )
        for profile, port in gate.CANONICAL_PORTS.items()
    }
    return gate.Binding(
        expected_commit="a" * 40,
        connect_ip="127.0.0.1",
        pinned_ca_pem=tmp_path / "ca.pem",
        expected_leaf_der_sha256="b" * 64,
        transport_gate_script=tmp_path / "three_origin_gate.py",
        transport_gate_script_sha256="c" * 64,
        transport_evidence=tmp_path / "transport.json",
        session_cookie_name="session",
        origins=origins,
    )


def _transport_fixture(binding: gate.Binding):
    listeners = {}
    receipts = {}
    for offset, profile in enumerate(gate.PROFILES, start=1):
        port = gate.CANONICAL_PORTS[profile]
        listeners[profile] = {
            "profile": profile,
            "local_address": binding.connect_ip,
            "local_port": port,
            "owning_pid": 1000 + offset,
            "state": "Listen",
        }
        receipts[profile] = {
            "profile": profile,
            "status": "started",
            "pid": 1000 + offset,
            "bind": f"{binding.connect_ip}:{port}",
            "receipt_sha256": f"{offset}" * 64,
        }
    evidence = {
        "listener_checks": {
            "before_origin_probes": listeners,
            "after_origin_probes": listeners,
        },
        "start_receipts": receipts,
    }
    summary = {
        "transport_tool_sha256": binding.transport_gate_script_sha256,
        "transport_evidence_sha256": "d" * 64,
        "source_commit": binding.expected_commit,
        "connect_ip": binding.connect_ip,
    }
    return summary, evidence


class _FakeClient:
    def __init__(
        self,
        binding: gate.Binding,
        origin: gate.OriginBinding,
        active_codes: dict[str, str],
        *,
        accept_wrong_for: str | None = None,
    ) -> None:
        self.binding = binding
        self.origin = origin
        self.active_codes = active_codes
        self.accept_wrong_for = accept_wrong_for
        self.authenticated = False

    def _response(self, status: int, path: str, body: bytes = b"") -> gate.HttpObservation:
        content_type = "text/csv; charset=utf-8" if path == gate.CATALOG_PATH else "text/html"
        return gate.HttpObservation(status, path, True, content_type, body)

    def login(self, access_code: str) -> gate.LoginObservation:
        expected = self.active_codes[self.origin.profile]
        accepted = access_code == expected or (
            self.accept_wrong_for == self.origin.profile and access_code != expected
        )
        self.authenticated = accepted
        response = self._response(200, "/" if accepted else "/login")
        contract = {
            "session_cookie_present": accepted,
            "session_cookie_rotated": accepted,
            "secure": accepted,
            "http_only": accepted,
            "same_site_lax": accepted,
            "path_root": accepted,
            "host_only": accepted,
        }
        cookie = f"session={self.origin.profile}-session" if accepted else None
        return gate.LoginObservation(accepted, response, contract, cookie)

    def catalog(self) -> gate.HttpObservation:
        if self.authenticated:
            body = b"Item Code,Item Name,Spec,Tray Image\nA,Name,Spec,image.png\n"
            return self._response(200, gate.CATALOG_PATH, body)
        return self._response(401, gate.CATALOG_PATH, b"{}")

    def catalog_with_cookie(self, cookie_header: str) -> gate.HttpObservation:
        expected = f"session={self.origin.profile}-session"
        if cookie_header == expected:
            body = b"Item Code,Item Name,Spec,Tray Image\nA,Name,Spec,image.png\n"
            return self._response(200, gate.CATALOG_PATH, body)
        return self._response(401, gate.CATALOG_PATH, b"{}")

    def logout_and_reprobe(self):
        self.authenticated = False
        return self._response(200, "/login"), self._response(401, gate.CATALOG_PATH, b"{}")


def _passing_database_probe(_path: Path) -> dict[str, object]:
    return {
        "query_only": True,
        "quick_check": "ok",
        "required_table_count": len(gate._REQUIRED_DB_TABLES),
        "missing_required_table_count": 0,
    }


def test_credential_free_dry_run_is_unknown_exit_2_and_writes_only_e(tmp_path, capsys):
    evidence = tmp_path / "dry-run.json"
    assert evidence.drive.casefold() == "e:"

    exit_code = gate.main(["dry-run", "--evidence", str(evidence)])

    assert exit_code == 2
    pointer = json.loads(capsys.readouterr().out)
    assert pointer["overall_status"] == "UNKNOWN"
    assert pointer["credentials_emitted"] is False
    document = json.loads(evidence.read_text(encoding="utf-8"))
    gate.validate_evidence_document(document)
    assert document["overall_status"] == "UNKNOWN"
    assert document["item_counts"]["UNKNOWN"] == len(gate._all_item_specs())
    assert document["state_change"]["performed"] is False


def test_credentials_are_stdin_only_exact_shape_and_repr_is_redacted():
    payload, values = _credential_payload()

    bundle = gate.load_credentials_from_stdin(io.BytesIO(payload))

    rendered = repr(bundle)
    for row in values.values():
        for secret_value in row.values():
            assert secret_value not in rendered


def test_live_fake_probe_passes_all_checks_without_emitting_secret_values(tmp_path):
    payload, raw_values = _credential_payload()
    credentials = gate.load_credentials_from_stdin(io.BytesIO(payload))
    binding = _binding(tmp_path)
    active_codes = {
        profile: credentials.origins[profile].active_access_code
        for profile in gate.PROFILES
    }

    document = gate.run_live(
        binding,
        credentials,
        client_factory=lambda bound, origin: _FakeClient(bound, origin, active_codes),
        transport_validator=lambda bound: _transport_fixture(bound),
        database_probe=_passing_database_probe,
    )

    gate.validate_evidence_document(document)
    assert document["overall_status"] == "PASS"
    assert document["item_counts"] == {
        "PASS": len(gate._all_item_specs()),
        "FAIL": 0,
        "UNKNOWN": 0,
    }
    serialized = json.dumps(document, sort_keys=True)
    for row in raw_values.values():
        for secret_value in row.values():
            assert secret_value not in serialized
    assert "inspection-session" not in serialized
    assert "label-session" not in serialized
    assert "container-session" not in serialized


def test_wrong_credential_acceptance_forces_nested_and_overall_fail(tmp_path):
    payload, _raw_values = _credential_payload()
    credentials = gate.load_credentials_from_stdin(io.BytesIO(payload))
    binding = _binding(tmp_path)
    active_codes = {
        profile: credentials.origins[profile].active_access_code
        for profile in gate.PROFILES
    }

    document = gate.run_live(
        binding,
        credentials,
        client_factory=lambda bound, origin: _FakeClient(
            bound, origin, active_codes, accept_wrong_for="inspection"
        ),
        transport_validator=lambda bound: _transport_fixture(bound),
        database_probe=_passing_database_probe,
    )

    by_id = {item["item_id"]: item for item in document["items"]}
    assert by_id["inspection.wrong_credential_rejected"]["status"] == "FAIL"
    assert document["overall_status"] == "FAIL"


def test_unknown_is_not_folded_to_pass_for_profile_validation(tmp_path):
    document = gate.dry_run_document()
    path = tmp_path / "unknown.json"
    gate.atomic_write_json(path, document)

    assert gate.selected_status(document, "inspection") == "UNKNOWN"
    assert gate.main(
        ["validate", "--input-evidence", str(path), "--profile", "inspection"]
    ) == 2


def test_malformed_top_level_status_is_rejected_fail_closed():
    document = gate.dry_run_document()
    document["overall_status"] = "PASS"

    with pytest.raises(gate.GateError, match="EVIDENCE_OVERALL_STATUS_INVALID"):
        gate.validate_evidence_document(document)


def test_expired_cookie_requires_single_bounded_cookie_pair():
    payload, _raw_values = _credential_payload()
    parsed = json.loads(payload)
    parsed["origins"]["inspection"]["expired_session_cookie"] = "session=value; Domain=example.test"

    with pytest.raises(gate.GateError, match="EXPIRED_SESSION_COOKIE_INVALID"):
        gate.load_credentials_from_stdin(io.BytesIO(json.dumps(parsed).encode("utf-8")))


def test_expired_cookie_name_must_match_frozen_session_cookie_binding(tmp_path):
    payload, _raw_values = _credential_payload()
    parsed = json.loads(payload)
    parsed["origins"]["inspection"]["expired_session_cookie"] = "other=expired"
    credentials = gate.load_credentials_from_stdin(
        io.BytesIO(json.dumps(parsed).encode("utf-8"))
    )

    with pytest.raises(gate.GateError, match="EXPIRED_SESSION_COOKIE_NAME_MISMATCH"):
        gate.run_live(
            _binding(tmp_path),
            credentials,
            transport_validator=lambda bound: _transport_fixture(bound),
            database_probe=_passing_database_probe,
        )


def test_state_changing_checks_are_explicitly_marked():
    document = gate.dry_run_document()
    by_id = {item["item_id"]: item for item in document["items"]}

    assert by_id["auth.state_change_approval"]["state_change"] == gate.SIDE_EFFECT_CLASS
    assert by_id["transport.baseline"]["state_change"] == "NONE_DIRECT"
    assert document["business_state_write_requested"] is False
    assert document["server_restart_or_configuration_change"] is False

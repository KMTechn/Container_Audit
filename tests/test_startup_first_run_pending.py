"""An app-completable first run is advisory; existing blockers still apply."""
import os
from pathlib import Path
import secrets

import pytest

import Container_Audit as app
import current_user_onboarding as onboarding
import data_generation_guard as guard
import item_catalog_sync as catalog
import startup_check as check
import startup_check_report as report
import user_relay
from kmtech_shared import data_generation as generation
from tests.test_administrator_installation_pending import machine_intent
from tests.test_current_user_onboarding import (
    _autostart, _credential_loader, _ledger_factory, _profile_loader, _ready_state,
    _relay_start, existing_possession_key_contract,
)
from tests.test_startup_check import _run_without_effects, _write_json, installed
from tests.test_startup_check_report import flow, folder, read_result, report_scope


def machine_pending(installed):
    marker = Path(os.environ["PROGRAMDATA"]) / "KMTech/ContainerAudit/machine-install/pending-onboarding.json"
    payload = dict(schema="container-audit-machine-pending-v1", status="PENDING",
                   install_id=secrets.token_hex(16), target_sid=installed.sid,
                   install_root=str(installed.app.parent), source_commit=installed.build,
                   version=installed.version)
    _write_json(marker, payload)
    return marker, payload


def remove_user_artifacts(installed):
    paths = installed.paths
    for path in (paths.identity_path, paths.producer_manifest_path, paths.credential_path,
                 paths.registration_report_path, paths.logistics_profile_path, paths.logistics_secret_path):
        path.unlink(missing_ok=True)
    for path in (installed.cache, catalog._cache_authority_path(installed.cache),
                 catalog._cache_recovery_path(installed.cache)):
        path.unlink(missing_ok=True)


@pytest.mark.parametrize("kind", ["machine", "user", "retryable_user"])
def test_first_start_can_finish_without_cli_side_effects(installed, monkeypatch, capsys, kind):
    remove_user_artifacts(installed)
    monkeypatch.setattr(user_relay, "_registry_get", lambda: "")
    if kind == "machine":
        machine_pending(installed)
    else:
        monkeypatch.setenv("CONTAINER_AUDIT_ENABLE_FIRST_RUN_ONBOARDING", "1")
        if kind == "retryable_user":
            _write_json(installed.paths.registration_report_path, {"status": "FAILED"})
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 0 and result["startable"]
    assert result["status"] == result["category"] == "READY"
    assert result["reasons"] == ["FIRST_RUN_PENDING"]
    assert result["categories"] == ["READY", "FIRST_RUN_PENDING"]


def test_machine_pending_with_ready_user_is_advisory(installed, monkeypatch, capsys):
    machine_pending(installed)
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 0 and result["reasons"] == ["FIRST_RUN_PENDING"]


@pytest.mark.parametrize("kind,exit_code,reason", [
    ("failed_user", 10, "FIRST_RUN_SETUP_REQUIRED"),
    ("recovery_user", 10, "FIRST_RUN_SETUP_REQUIRED"),
    ("failed_machine", 10, "MACHINE_ONBOARDING_PENDING"),
    ("wrong_account", 10, "ACCOUNT_MISMATCH"),
    ("corrupt_machine", 20, "UNKNOWN_ACCOUNT"),
    ("unknown_user", 20, "UNKNOWN_ACCOUNT"),
    ("disabled_user", 10, "FIRST_RUN_SETUP_REQUIRED"),
    ("wrong_relay", 10, "RELAY_AUTOSTART_MISMATCH"),
    ("data_floor", 10, "DATA_GUARD_REFUSED"),
    ("ready_user_no_catalog", 10, "ITEM_CATALOG_UNAVAILABLE"),
])
def test_first_run_does_not_hide_failure_or_unknown(installed, monkeypatch, capsys, kind, exit_code, reason):
    marker, payload = machine_pending(installed)
    if kind in {"failed_user", "recovery_user", "unknown_user"}:
        status = {"failed_user": "FAILED", "recovery_user": "RECOVERY_REQUIRED",
                  "unknown_user": "UNRECOGNIZED"}[kind]
        monkeypatch.setattr(onboarding, "inspect_current_user_state", lambda *_args, **_kwargs: {"status": status})
    elif kind == "failed_machine":
        monkeypatch.setattr(onboarding, "consume_pending_machine_onboarding",
                            lambda *_args, **_kwargs: {"status": "FAILED"})
    elif kind == "wrong_account":
        payload["target_sid"] = secrets.token_hex(16)
        _write_json(marker, payload)
    elif kind == "corrupt_machine":
        marker.write_bytes(b"{}")
    elif kind == "disabled_user":
        marker.unlink()
        remove_user_artifacts(installed)
        monkeypatch.setenv("CONTAINER_AUDIT_ENABLE_FIRST_RUN_ONBOARDING", "off")
    elif kind == "wrong_relay":
        monkeypatch.setattr(user_relay, "_registry_get", lambda: "unexpected registration")
    elif kind == "data_floor":
        generation.record_generation(
            guard.marker_paths(installed.paths.data_root, installed.sid)[1],
            app_id="container_audit", subject_sid=installed.sid, version="v9.0.0",
            build_id=installed.build, data_compatible_min_version="v9.0.0")
    else:
        for path in (installed.cache, catalog._cache_authority_path(installed.cache),
                     catalog._cache_recovery_path(installed.cache)):
            path.unlink()
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == exit_code and not result["startable"]
    assert reason in result["reasons"]


@pytest.mark.parametrize("status,machine,enabled,reason", [
    ("READY", False, False, None), ("READY", True, False, None),
    ("PENDING", True, False, "FIRST_RUN_PENDING"),
    ("ABSENT", False, True, "FIRST_RUN_PENDING"),
    ("ABSENT_RETRYABLE", False, True, "FIRST_RUN_PENDING"),
    ("ABSENT", False, False, "FIRST_RUN_SETUP_REQUIRED"),
    ("RECOVERY_REQUIRED", False, True, "FIRST_RUN_SETUP_REQUIRED"),
    ("FAILED", False, True, "FIRST_RUN_SETUP_REQUIRED"),
    ("FAILED", True, True, "MACHINE_ONBOARDING_PENDING"),
    ("UNRECOGNIZED", False, True, "UNKNOWN_ACCOUNT"),
])
def test_shared_state_classifier(status, machine, enabled, reason):
    assert onboarding.startup_onboarding_reason(
        {"status": status}, machine=machine, can_onboard=enabled) == reason


def test_advisory_pending_does_not_mask_unknown_exception():
    report.begin(app.CURRENT_VERSION)
    report.note("FIRST_RUN_PENDING")
    captured = []
    original = report._write_result
    try:
        report._write_result = lambda result: captured.append(result) or True
        report.finish(failed=True)
    finally:
        report._write_result = original
    assert captured[0]["reasons"] == ["FIRST_RUN_PENDING", "UNKNOWN_CHECK"]
    assert not captured[0]["startable"] and captured[0]["category"] == "UNKNOWN"


def test_real_machine_onboarding_reports_shared_pending_once(folder, machine_intent):
    marker, _, calls, completed, consume = machine_intent
    before = marker.read_bytes()
    report.begin(app.CURRENT_VERSION)
    assert consume()["status"] == "READY"
    report.finish()
    result = read_result(folder)
    assert result["reasons"] == ["FIRST_RUN_PENDING"] and result["startable"]
    assert result["category"] == "READY" and result["categories"] == ["READY", "FIRST_RUN_PENDING"]
    assert len(calls) == len(completed) == 1 and marker.read_bytes() == before


def test_real_machine_onboarding_failure_keeps_existing_refusal(folder, flow, machine_intent):
    marker, _, _, completed, consume = machine_intent
    before = marker.read_bytes()
    report.begin(app.CURRENT_VERSION)
    with pytest.raises(onboarding.CurrentUserOnboardingError) as failure:
        consume(onboarder=lambda *_args, **_kwargs: {"status": "FAILED"})
    app._show_first_run_onboarding_error(failure.value)
    result = read_result(folder)
    assert result["reasons"] == ["FIRST_RUN_PENDING", "FIRST_RUN_SETUP_REQUIRED"]
    assert not result["startable"] and result["category"] == "ACCOUNT_MISMATCH"
    assert flow.notices == [report.NOTICE] and not completed and marker.read_bytes() == before


def test_real_user_onboarding_uses_existing_inspection_and_reports_pending(folder, tmp_path, monkeypatch,
                                                                         existing_possession_key_contract):
    app_root = tmp_path / "first-app"
    app_root.mkdir()
    environment = {"APPDATA": str(tmp_path / "first-user"),
                   "LOCALAPPDATA": str(tmp_path / "first-local"),
                   onboarding.DATA_ROOT_ENV: str(tmp_path / "first-data")}
    paths = onboarding.resolve_current_user_onboarding_paths(app_root, environ=environment)
    assert all(path.resolve().is_relative_to(tmp_path.resolve()) for path in (
        paths.data_root, paths.direct_sync_root, paths.logistics_profile_path, paths.bootstrap_tls_ca_bundle_path))
    initial = onboarding.inspect_current_user_state(paths)
    registration = []
    def register(selected_paths):
        registration.append(True)
        _ready_state(selected_paths)
        return 0
    report.begin(app.CURRENT_VERSION)
    result = onboarding.onboard_current_user(
        app_root, environ=environment, require_bootstrap_integrity=False,
        registration_runner=register, profile_loader=_profile_loader,
        credential_loader=_credential_loader, ledger_factory=_ledger_factory,
        autostart_installer=_autostart, relay_launcher=_relay_start)
    report.finish()
    assert result["status"] == "READY" and registration == [True]
    assert read_result(folder)["reasons"] == [onboarding.startup_onboarding_reason(initial, can_onboard=True)]

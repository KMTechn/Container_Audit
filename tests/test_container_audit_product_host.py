import json
import sys

import pytest

import container_audit_product_host as product_host
import current_user_onboarding
from tools import direct_sync_relay_runner
import user_relay


def test_non_product_arguments_continue_to_gui_startup():
    assert product_host.dispatch_product_mode([]) is None
    assert product_host.dispatch_product_mode(["--ordinary-app-argument"]) is None


def test_relay_mode_reuses_main_process_and_forwards_arguments(monkeypatch):
    observed = []

    def fake_main(arguments):
        observed.append(list(arguments))
        return 17

    monkeypatch.setattr(direct_sync_relay_runner, "main", fake_main)

    result = product_host.dispatch_product_mode(
        [product_host.DIRECT_SYNC_RELAY_MODE, "--db-path", "queue.sqlite3"]
    )

    assert result == 17
    assert observed == [["--db-path", "queue.sqlite3"]]


def test_windowed_host_supplies_and_restores_output_streams(monkeypatch):
    observed = []

    def fake_main(arguments):
        observed.append(
            (sys.stdout is not None, sys.stderr is not None, list(arguments))
        )
        return 0

    monkeypatch.setattr(direct_sync_relay_runner, "main", fake_main)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)

    assert (
        product_host.dispatch_product_mode([product_host.DIRECT_SYNC_RELAY_MODE]) == 0
    )
    assert observed == [(True, True, [])]
    assert sys.stdout is None
    assert sys.stderr is None


def test_relay_mode_converts_unhandled_exception_to_bounded_durable_diagnostics(
    monkeypatch, tmp_path
):
    runtime_status_path = tmp_path / "status" / "runtime.json"
    log_path = tmp_path / "logs" / "runtime.jsonl"
    secret_text = "secret=must-not-be-persisted"

    def fail(_arguments):
        raise RuntimeError(secret_text)

    monkeypatch.setattr(direct_sync_relay_runner, "main", fail)

    result = product_host.dispatch_product_mode(
        [
            product_host.DIRECT_SYNC_RELAY_MODE,
            "--runtime-status-path",
            str(runtime_status_path),
            "--log-path",
            str(log_path),
            "--worker-id",
            "relay-worker",
        ]
    )

    assert result == product_host.HOSTED_RELAY_FAILURE_EXIT_CODE
    status = json.loads(runtime_status_path.read_text(encoding="utf-8"))
    event = json.loads(log_path.read_text(encoding="utf-8"))
    assert status["status"] == "runtime_error"
    assert status["error_code"] == "hosted_relay_unhandled_exception"
    assert status["worker_id"] == "relay-worker"
    assert event["event"] == "hosted_relay_unhandled_exception"
    assert event["error_type"] == "RuntimeError"
    assert secret_text not in runtime_status_path.read_text(encoding="utf-8")
    assert secret_text not in log_path.read_text(encoding="utf-8")
    assert runtime_status_path.stat().st_size < 16 * 1024
    assert log_path.stat().st_size < 16 * 1024


def test_relay_mode_preserves_system_exit_semantics(monkeypatch):
    def exit_runner(_arguments):
        raise SystemExit(7)

    monkeypatch.setattr(direct_sync_relay_runner, "main", exit_runner)

    with pytest.raises(SystemExit) as caught:
        product_host.dispatch_product_mode([product_host.DIRECT_SYNC_RELAY_MODE])

    assert caught.value.code == 7


def test_user_relay_mode_reuses_main_process(monkeypatch):
    observed = []
    monkeypatch.setattr(
        user_relay,
        "main",
        lambda arguments: observed.append(list(arguments)) or 0,
    )

    result = product_host.dispatch_product_mode(
        [product_host.USER_RELAY_MODE, "--once"]
    )

    assert result == 0
    assert observed == [["--once"]]


def test_current_user_product_modes_dispatch_in_process(monkeypatch):
    observed = []
    monkeypatch.setattr(
        current_user_onboarding,
        "onboarding_main",
        lambda arguments: observed.append(("onboard", list(arguments))) or 0,
    )
    monkeypatch.setattr(
        current_user_onboarding,
        "removal_main",
        lambda arguments: observed.append(("remove", list(arguments))) or 0,
    )
    monkeypatch.setattr(
        current_user_onboarding,
        "replacement_lifecycle_restore_main",
        lambda arguments: observed.append(("restore", list(arguments))) or 0,
    )

    assert (
        product_host.dispatch_product_mode(
            [product_host.ONBOARD_CURRENT_USER_MODE, "--app-root", "app"]
        )
        == 0
    )
    assert (
        product_host.dispatch_product_mode(
            [product_host.REMOVE_CURRENT_USER_MODE, "--app-root", "app"]
        )
        == 0
    )
    restore_arguments = [
        "--app-root",
        "current/app",
        "--code-root",
        "current",
        "--replacement-transaction-id",
        "a" * 32,
        "--replacement-receipt-path",
        "receipt.json",
        "--replacement-receipt-sha256",
        "b" * 64,
        "--writer-contract-sha256",
        "c" * 64,
        "--report-path",
        "lifecycle.json",
        "--session-id",
        "d" * 32,
        "--attempt-id",
        "e" * 32,
        "--session-started-at-utc",
        "2026-08-30T00:00:00+00:00",
        "--orchestrator-sha256",
        "f" * 64,
    ]
    assert (
        product_host.dispatch_product_mode(
            [product_host.RESTORE_CURRENT_USER_LIFECYCLE_MODE, *restore_arguments]
        )
        == 0
    )
    assert observed == [
        ("onboard", ["--app-root", "app"]),
        ("remove", ["--app-root", "app"]),
        ("restore", restore_arguments),
    ]

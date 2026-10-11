"""Refusal guidance requires a confirmed public result, with fixed catalog causes."""
import io
from pathlib import Path

import pytest

import Container_Audit as app
import startup_check as check
import startup_check_report as report
from tests.test_startup_check_report import flow, folder, read_result, report_scope


@pytest.mark.parametrize("failure", ["missing", "open", "replace", "read", "mismatch"])
@pytest.mark.parametrize("refusal", ["data", "catalog"])
def test_unconfirmed_report_preserves_original_message_and_exit(
        folder, flow, monkeypatch, failure, refusal):
    errors = []
    monkeypatch.setattr(app.messagebox, "showerror", lambda *args: errors.append(args))
    original_open = Path.open

    def denied(*_args, **_kwargs):
        raise PermissionError()

    if failure == "missing":
        folder.rmdir()
    elif failure == "replace":
        monkeypatch.setattr(report.os, "replace", denied)
    else:
        def open_file(path, mode="r", *args, **kwargs):
            if failure == "open" and mode == "x":
                raise PermissionError()
            if mode == "rb" and failure == "read":
                raise PermissionError()
            if mode == "rb" and failure == "mismatch":
                return io.BytesIO(b"{}\n")
            return original_open(path, mode, *args, **kwargs)
        monkeypatch.setattr(Path, "open", open_file)

    blocked = app.DataGenerationBlocked({"status": "REFUSE", "allowed": False})

    def prepare(**_kwargs):
        if refusal == "data":
            raise blocked
        app._show_item_catalog_startup_error("REQUEST_FAILED_NO_CACHE", http_status_code=403)
        return app.ITEM_CATALOG_STARTUP_EXIT_CODE

    monkeypatch.setattr(app, "_prepare_gui_startup", prepare)
    assert app.main([]) == (1 if refusal == "data" else app.ITEM_CATALOG_STARTUP_EXIT_CODE)
    assert not flow.notices
    if refusal == "data":
        assert errors == [("자료 판 확인", blocked.user_message)]
    else:
        assert len(errors) == 1 and errors[0][0] == app.ITEM_CATALOG_STARTUP_ERROR_TITLE
        assert "403" in errors[0][1] and "REQUEST_FAILED_NO_CACHE" in errors[0][1]


def test_confirmed_403_report_uses_notice_and_records_fixed_cause(folder, flow, monkeypatch):
    def prepare(**_kwargs):
        app._show_item_catalog_startup_error(
            "REQUEST_FAILED_NO_CACHE", http_status_code=403, exception_type="HTTPError")
        return app.ITEM_CATALOG_STARTUP_EXIT_CODE
    monkeypatch.setattr(app, "_prepare_gui_startup", prepare)
    assert app.main([]) == app.ITEM_CATALOG_STARTUP_EXIT_CODE
    assert flow.notices == [report.NOTICE] and not flow.legacy
    result = read_result(folder)
    assert result["reasons"] == ["ITEM_CATALOG_UNAVAILABLE", "ITEM_CATALOG_HTTP_403"]
    assert result["categories"] == ["CATALOG_OFFLINE"]


def test_previous_success_does_not_hide_later_confirmation_failure(folder, monkeypatch):
    report.begin(app.CURRENT_VERSION)
    assert report.publish("DATA_GUARD_REFUSED", refused=True)
    original_open = Path.open
    def cannot_confirm(path, mode="r", *args, **kwargs):
        if mode == "rb":
            raise PermissionError()
        return original_open(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, "open", cannot_confirm)
    assert not report.publish(refused=True)


@pytest.mark.parametrize("cause,status,exception,expected", [
    ("REQUEST_FAILED_NO_CACHE", 403, "HTTPError", "ITEM_CATALOG_HTTP_403"),
    ("REQUEST_FAILED_NO_CACHE", 503, "HTTPError", "ITEM_CATALOG_HTTP_ERROR"),
    ("REQUEST_FAILED_NO_CACHE", None, "Timeout", "ITEM_CATALOG_TIMEOUT"),
    ("REQUEST_FAILED_NO_CACHE", None, "ConnectTimeout", "ITEM_CATALOG_TIMEOUT"),
    ("REQUEST_FAILED_NO_CACHE", None, "ReadTimeout", "ITEM_CATALOG_TIMEOUT"),
    ("REQUEST_FAILED_NO_CACHE", None, "TimeoutError", "ITEM_CATALOG_TIMEOUT"),
    ("REQUEST_FAILED_NO_CACHE", None, "ConnectionError", "ITEM_CATALOG_UNREACHABLE"),
    ("REQUEST_FAILED_NO_CACHE", None, "SSLError", "ITEM_CATALOG_UNREACHABLE"),
    ("REQUEST_FAILED_NO_CACHE", None, None, "ITEM_CATALOG_REQUEST_FAILED_NO_CACHE"),
    ("PROFILE_LOAD_FAILED", None, "ValueError", "ITEM_CATALOG_PROFILE_LOAD_FAILED"),
    ("SNAPSHOT_PARSE_FAILED", None, None, "ITEM_CATALOG_SNAPSHOT_PARSE_FAILED"),
    (None, None, None, "UNKNOWN_CATALOG"),
    ("UNRECOGNIZED", 403, "HTTPError", "UNKNOWN_CATALOG"),
    ("REQUEST_FAILED_NO_CACHE", None, "UnrecognizedFailure", "UNKNOWN_CATALOG"),
])
def test_catalog_cause_projection_has_only_allowed_fixed_codes(cause, status, exception, expected):
    reason = check.catalog_refusal_reason(cause, http_status_code=status, exception_type=exception)
    assert reason == expected
    result = check.startup_result(reasons=[reason])
    assert result["reasons"] == [expected]
    assert result["category"] == ("UNKNOWN" if expected == "UNKNOWN_CATALOG" else "CATALOG_OFFLINE")


def test_all_existing_catalog_causes_are_allowlisted():
    import item_catalog_sync
    for cause in item_catalog_sync.ITEM_CATALOG_CAUSE_CODES:
        assert check.catalog_refusal_reason(cause) == "ITEM_CATALOG_" + cause

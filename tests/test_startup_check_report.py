"""Compare G0 with the baseline entrypoint; all windows are fake widgets."""
import ast
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import types

import pytest

import auto_update
import Container_Audit as app
import ca_screen_bridge as screen
import startup_check as check
import startup_check_report as report
import writer_session_fence as fence

ROOT = Path(__file__).resolve().parents[1]
BASE = "fd8ceb3ded57182f728779e46db8ccd4a22f051b"


@pytest.fixture(autouse=True)
def report_scope():
    report.finish()
    yield
    report.finish()


@pytest.fixture
def folder():
    path = Path(os.environ["PROGRAMDATA"]) / "KMTech/start-check"
    path.mkdir(parents=True)
    return path


def read_result(folder):
    paths = list(folder.glob("*-CA.json"))
    assert len(paths) == 1 and len(list(folder.iterdir())) == 1
    assert len(paths[0].name) == 16 and paths[0].name[:8].isdigit()
    raw = paths[0].read_text(encoding="utf-8")
    assert len(raw.splitlines()) == 1 and raw.endswith("\n")
    result = json.loads(raw)
    assert set(result) == {"schema", "app", "version", "build_sha", "startable",
                           "status", "reasons", "category", "categories", "checked_at"}
    assert result["schema"] == "app_startup_check.v1" and result["app"] == "CA"
    return result


@pytest.fixture
def flow(monkeypatch):
    events, notices, legacy = [], [], []
    lease = types.SimpleNamespace(release=lambda: events.append("release"))
    window = types.SimpleNamespace(run=lambda: events.append("run"))
    monkeypatch.setattr(auto_update, "startup_gate", lambda *_args: events.append("gate"))
    monkeypatch.setattr(auto_update, "trial_context", lambda *_args: None)
    monkeypatch.setattr(app, "dispatch_product_mode", lambda _args: events.append("host"))
    monkeypatch.setattr(app, "_prepare_gui_startup",
                        lambda **_kwargs: (events.append("prepare") or window, lease))
    monkeypatch.setattr(app, "_show_startup_unavailable", lambda: notices.append(report.NOTICE))
    monkeypatch.setattr(app.messagebox, "showerror", lambda *_args: legacy.append("error"))
    monkeypatch.setattr(app.messagebox, "showwarning", lambda *_args: legacy.append("warning"))
    monkeypatch.setattr(check, "check_startup",
                        lambda *_args: pytest.fail("app must never run the standalone checker"))
    # This fixture owns a resident-UI double, and measures startup observation
    # and refusal semantics. Screen selection and availability have their own
    # entry tests; give this UI double the same runner boundary on both routes.
    def resident_runner(module):
        def run(arguments):
            module.CA_SCREEN_HOST["requested"] = False
            return module._run_gui_application(arguments)
        return run
    monkeypatch.setattr(screen, "screen_runner", resident_runner)
    return types.SimpleNamespace(events=events, notices=notices, legacy=legacy, lease=lease, window=window)


@pytest.fixture(scope="module")
def baseline_code():
    completed = subprocess.run(["git", "-c", "core.autocrlf=false", "show", BASE + ":Container_Audit.py"],
                               cwd=ROOT, capture_output=True, timeout=20)
    assert completed.returncode == 0
    tree = ast.parse(completed.stdout.decode("utf-8-sig"))
    original = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    original.name = "baseline_main"
    namespace = {}
    exec(compile(ast.Module(body=[original], type_ignores=[]), "<baseline-main>", "exec"), namespace)
    return namespace["baseline_main"].__code__


def outcome(function):
    try:
        result = function([])
        return 0 if result is None else result
    except (fence.WriterFencedError, RuntimeError) as failure:
        return ("exception", type(failure))  # Preserve uncaught refusal semantics as well as process exit.


@pytest.mark.parametrize("case,category", [
    ("ready", "READY"), ("warning", "READY"), ("duplicate", "READY"),
    ("bootstrap", "UPDATE_PENDING"), ("wrong_account", "ACCOUNT_MISMATCH"),
    ("data_floor", "DATA_GUARD"), ("data_unreadable", "UNKNOWN"),
    ("onboarding", "ACCOUNT_MISMATCH"), ("catalog", "CATALOG_OFFLINE"),
    ("deploy_fence", "DEPLOY_FENCE"), ("unexpected_existing", "UNKNOWN"),
    ("install_mismatch", "INSTALL_MISMATCH"), ("machine_fence", "DEPLOY_FENCE"),
    ("factory_mismatch", "INSTALL_MISMATCH"),
])
def test_g0_matches_baseline_exit_and_adds_no_refusal(
        folder, flow, baseline_code, monkeypatch, tmp_path, case, category):
    if case in {"bootstrap", "wrong_account"}:
        monkeypatch.setattr(auto_update, "startup_gate", lambda *_args: 0 if case == "bootstrap" else 20)
    if case == "factory_mismatch":
        def invalid_contract(*_args, **_kwargs):
            raise RuntimeError("fixture contract mismatch")
        monkeypatch.setattr(app, "load_and_verify_contract_lock", invalid_contract)

    def prepare(**_kwargs):
        flow.events.append("prepare")
        if case in {"data_floor", "data_unreadable"}:
            raise app.DataGenerationBlocked({"status": "REFUSE" if case == "data_floor" else "UNKNOWN",
                                             "allowed": False})
        if case == "deploy_fence":
            raise fence.WriterFencedError("ACTIVE_WRITER_FENCE", "fixture fence")
        if case == "install_mismatch":
            from current_user_onboarding import BootstrapIntegrityMismatch
            blocked = app.DataGenerationBlocked({"status": "UNKNOWN", "allowed": False})
            blocked.__cause__ = BootstrapIntegrityMismatch("fixture inventory mismatch")
            raise blocked
        if case == "unexpected_existing":
            raise RuntimeError("fixture existing fault")
        if case == "factory_mismatch":
            app.verify_factory_contract_startup()
        if case in {"onboarding", "machine_fence"}:
            failure = app.CurrentUserOnboardingError("fixture setup", report_path=tmp_path, status="FAILED")
            if case == "machine_fence":
                from current_user_onboarding import MachineDeploymentFenced
                failure.__cause__ = MachineDeploymentFenced("fixture placement fence")
            app._show_first_run_onboarding_error(failure)
            return app.ONBOARDING_EXIT_CODE
        if case == "catalog":
            app._show_item_catalog_startup_error("fixture_catalog")
            return app.ITEM_CATALOG_STARTUP_EXIT_CODE
        if case == "duplicate":
            app._startup_check_observe("note", "ALREADY_RUNNING")
            return None
        if case == "warning":
            app._show_bootstrap_integrity_warning(tmp_path)
        return flow.window, flow.lease

    monkeypatch.setattr(app, "_prepare_gui_startup", prepare)
    baseline = types.FunctionType(baseline_code, app.__dict__)
    before = outcome(baseline)
    before_events = list(flow.events)
    assert not list(folder.iterdir()) and not flow.notices
    flow.events.clear()
    flow.legacy.clear()
    after = outcome(app.main)
    assert after == before
    assert flow.events == before_events
    result = read_result(folder)
    assert result["category"] == category
    known_refusals = {"wrong_account", "data_floor", "data_unreadable", "onboarding", "catalog", "deploy_fence",
                      "install_mismatch", "machine_fence"}
    known_refusals.update({"factory_mismatch", "unexpected_existing"})
    assert len(flow.notices) == int(case in known_refusals)
    assert all(notice == report.NOTICE for notice in flow.notices)
    if case in {"ready", "warning", "duplicate"}:
        assert result["startable"]
    if case == "duplicate":
        assert result["categories"] == ["READY", "ALREADY_RUNNING"]


@pytest.mark.parametrize("category", [
    "UPDATE_PENDING", "DEPLOY_FENCE", "INSTALL_MISMATCH", "DATA_GUARD",
    "ACCOUNT_MISMATCH", "CATALOG_OFFLINE", "ALREADY_RUNNING", "UNKNOWN",
    "FIRST_RUN_PENDING",
])
def test_test_only_category_forces_result_without_changing_normal_start(
        folder, flow, monkeypatch, category):
    monkeypatch.setenv("KMTECH_START_CHECK_TEST_CATEGORY", category)
    assert app.main([]) == 0
    result = read_result(folder)
    assert result["category"] == ("READY" if category in check.NONBLOCKING_CATEGORIES else category)
    assert category in result["categories"]
    assert flow.events == ["gate", "host", "prepare", "run", "release"]
    assert not flow.notices


def test_observer_exception_reports_unknown_and_keeps_normal_start(folder, flow, monkeypatch):
    private_error = secrets.token_urlsafe(24)

    def failed_identity(*_args):
        raise RuntimeError(private_error)

    monkeypatch.setattr(report, "release_identity", failed_identity)
    def gate(*_args):
        flow.events.append("gate")
        app._startup_check_observe("release_identity", {"version": app.CURRENT_VERSION})
    monkeypatch.setattr(auto_update, "startup_gate", gate)
    assert app.main([]) == 0
    result = read_result(folder)
    assert result["category"] == "UNKNOWN"
    assert bool(private_error not in json.dumps(result))
    assert "run" in flow.events and not flow.notices


def test_begin_exception_is_unknown_and_adds_no_refusal(folder, flow, monkeypatch):
    monkeypatch.setattr(report, "begin", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError()))
    assert app.main([]) == 0
    assert read_result(folder)["category"] == "UNKNOWN"
    assert not flow.notices


@pytest.mark.parametrize("failure", ["replace", "open", "missing", "relative", "reparse"])
def test_result_write_failure_does_not_change_start(folder, flow, monkeypatch, failure):
    with monkeypatch.context() as faults:
        def denied(*_args, **_kwargs):
            raise PermissionError()
        if failure == "replace":
            faults.setattr(report.os, "replace", denied)
        elif failure == "open":
            faults.setattr(Path, "open", denied)
        elif failure == "missing":
            folder.rmdir()
        elif failure == "relative":
            faults.setenv("PROGRAMDATA", "relative")
        else:
            faults.setattr(report, "_assert_no_reparse_components", denied)
        assert app.main([]) == 0
        assert not flow.notices and "run" in flow.events
        assert not folder.exists() or not list(folder.iterdir())


def test_report_is_atomic_sanitized_and_never_acquires_admission(folder, monkeypatch):
    effects, replacements = [], []
    def denied(*_args, **_kwargs):
        effects.append(True)
        raise AssertionError("report acquired admission or network")
    monkeypatch.setattr(fence, "writer_admission", denied)
    monkeypatch.setattr(fence, "_acquire_named_mutex", denied)
    monkeypatch.setattr(fence, "active_fence", denied)
    original = os.replace
    def replace(source, destination):
        assert source.parent == destination.parent == folder
        assert json.loads(source.read_text())["schema"] == "app_startup_check.v1"
        replacements.append(True)
        original(source, destination)
    monkeypatch.setattr(report.os, "replace", replace)
    report.begin(app.CURRENT_VERSION)
    report.release_identity({"version": app.CURRENT_VERSION, "build_id": hashlib.sha1(str(folder).encode()).hexdigest()})
    report.note("DATA_GUARD_REFUSED")
    report.publish()
    report.finish()
    result = read_result(folder)
    assert result["category"] == "DATA_GUARD"
    assert replacements == [True] and not effects


def test_report_only_registration_cannot_be_used_by_other_sinks():
    with pytest.raises(fence.WriterFencedError) as rejected:
        fence.writer_sink("fixture_other_sink", report_only=True)(lambda: None)
    assert rejected.value.code == "REPORT_ONLY_SINK_NOT_ALLOWED"


def test_report_does_not_run_under_writer_admission(folder, monkeypatch):
    monkeypatch.setattr(fence._WRITER_LOCAL, "depth", 1, raising=False)
    with pytest.raises(fence.WriterFencedError) as rejected:
        report._write_result(check.startup_result())
    assert rejected.value.code == "STARTUP_REPORT_ADMISSION_HELD"
    assert not list(folder.iterdir())


def test_unknown_fields_and_raw_reasons_are_never_persisted(folder):
    private_value = secrets.token_urlsafe(24)
    result = check.startup_result()
    result.update(raw=private_value, path=str(folder), sid=private_value)
    result["reasons"] = [private_value]
    report._write_result(result)
    public = read_result(folder)
    assert public["reasons"] == ["UNKNOWN_CHECK"]
    assert bool(private_value not in json.dumps(public))


def test_notice_has_one_exact_line_and_only_close_button(monkeypatch):
    widgets, destroyed = [], []
    class Window:
        def title(self, *_args): pass
        def resizable(self, *_args): pass
        def protocol(self, *_args): pass
        def mainloop(self): pass
        def destroy(self): destroyed.append(True)
    class Widget:
        def __init__(self, _parent, **options):
            widgets.append(options)
        def pack(self, **_options): pass
    monkeypatch.setattr(app.tk, "Tk", Window)
    monkeypatch.setattr(app.tk, "Label", Widget)
    monkeypatch.setattr(app.tk, "Button", Widget)
    app._show_startup_unavailable()
    assert [item["text"] for item in widgets] == [report.NOTICE, "닫기"]
    assert "\n" not in report.NOTICE
    assert destroyed
    widgets[1]["command"]()
    assert len(destroyed) == 2


@pytest.mark.parametrize("mode", list(__import__("container_audit_product_host").PRODUCT_MODES))
def test_product_modes_never_write_gui_report_or_show_notice(folder, flow, monkeypatch, mode):
    monkeypatch.setattr(app, "dispatch_product_mode", lambda _args: 0)
    assert app.main([mode]) == 0
    assert not list(folder.iterdir()) and not flow.notices

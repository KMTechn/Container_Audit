"""The new screen goes through the existing startup; all windows are fake."""
from types import SimpleNamespace
from threading import Event, Thread
import sys

import pytest

import auto_update as updates
import Container_Audit as ca
import ca_screen_bridge as screen
from screen_startup_fallback import ScreenLaunchAttempt, ScreenStartupUnavailable


@pytest.fixture
def entry(monkeypatch):
    events, callbacks, failures, refusals, releases, host_calls = [], [], [], [], [], []
    host = {"requested": False, "active": False, "run": None}
    monkeypatch.setattr(ca, "CA_SCREEN_HOST", host)
    monkeypatch.setattr(sys, "path", list(sys.path))
    original_names = {name: getattr(ca, name)
                      for name in ("messagebox", "simpledialog", "filedialog", "play_sound")}
    original_tk, original_module = ca.tk.Tk, screen.ca
    existing_refusal = ca._startup_refusal

    def after(delay, callback):
        callbacks.append((delay, callback))
        return len(callbacks)

    root = SimpleNamespace(after=after, after_cancel=lambda _job: None,
                           withdraw=lambda: events.append("withdraw"),
                           deiconify=lambda: events.append("deiconify"))
    app = SimpleNamespace(root=root, run=lambda: events.append("app.run"),
                          on_closing=lambda **kw: events.append(("closing", kw)),
                          _finalize_application_close=lambda: events.append("finalize"))
    lease = SimpleNamespace(release=lambda: releases.append(True))
    bridge = SimpleNamespace(
        attach_owner=lambda processor: events.append("attach_owner"),
        fail_owner=lambda error: failures.append(error),
        request_exit=lambda: events.append("request_exit"),
        pump=lambda: True,
        _view_count=0,
    )
    def attached(processor):
        events.append("attach_owner")
        bridge._view_count = 1  # This fixture represents an already-ready shell.
    bridge.attach_owner = attached

    def prepare(**kwargs):
        events.append("prepare")
        state.data_root = kwargs["data_root"]
        return app, lease

    def startup_gate(_root, arguments):
        events.append("startup_gate")
        state.gate_arguments = list(arguments)
        return state.gate_result

    def dispatch(arguments):
        events.append("dispatch_product_mode")
        return state.product_result

    def observe(action, *_args, **_kwargs):
        if action == "begin":
            events.append("begin")
        return False

    def refuse(reason, **kwargs):
        refusals.append((reason, kwargs))
        return True

    def run_app(profile, data, **kwargs):
        events.append("run_app")
        host_calls.append((profile, data, kwargs))
        kwargs["owner_main"](bridge)
        if failures:
            raise failures[-1]
        return 99  # The shell's value differs from the existing GUI's value.

    state = SimpleNamespace(events=events, callbacks=callbacks, app=app, bridge=bridge,
                            failures=failures, refusals=refusals, releases=releases,
                            host_calls=host_calls, gate_result=None, product_result=None,
                            existing_refusal=existing_refusal)
    monkeypatch.setattr(ca, "_prepare_gui_startup", prepare)
    monkeypatch.setattr(ca, "dispatch_product_mode", dispatch)
    monkeypatch.setattr(ca, "_startup_check_observe", observe)
    monkeypatch.setattr(ca, "_startup_refusal", refuse)
    monkeypatch.setattr(updates, "startup_gate", startup_gate)
    monkeypatch.setattr(updates, "trial_context", lambda _root: None)
    monkeypatch.setattr(updates, "trial_stop_requested", lambda _root: False)
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=run_app))
    monkeypatch.setitem(sys.modules, "webview", SimpleNamespace(windows=[]))
    monkeypatch.setattr(screen, "_prepare_screen_backend", lambda _module: None)
    yield state
    assert host == {"requested": False, "active": False, "run": None}
    assert ca.tk.Tk is original_tk and screen.ca is original_module
    assert all(getattr(ca, name) is value for name, value in original_names.items())
    assert ca._startup_refusal is refuse


def test_old_screen_runs_the_existing_gui_and_releases_its_lease(entry, monkeypatch):
    def unexpected(_module):
        pytest.fail("screen_runner called with the emergency flag")

    monkeypatch.setattr(screen, "screen_runner", unexpected)
    original_gui = ca._run_gui_application

    def gui(arguments):
        entry.events.append("gui")
        return original_gui(arguments)

    monkeypatch.setattr(ca, "_run_gui_application", gui)
    assert ca.main([ca.CA_OLD_SCREEN_ARGUMENT]) == 0
    assert entry.events == ["begin", "startup_gate", "dispatch_product_mode", "gui", "prepare", "app.run"]
    assert entry.releases == [True] and not entry.host_calls


@pytest.mark.parametrize("alias", [False, True])
def test_default_and_new_screen_keep_gate_order_arguments_and_gui_exit_value(entry, tmp_path, alias):
    arguments = ([ca.CA_NEW_SCREEN_ARGUMENT] if alias else []) + ["--data-root", str(tmp_path)]
    assert ca.main(arguments) == 0
    assert entry.events == ["begin", "startup_gate", "dispatch_product_mode", "run_app",
                            "prepare", "attach_owner", "app.run", "request_exit"]
    assert entry.gate_arguments == arguments and entry.data_root == str(tmp_path)
    assert entry.releases == [True]
    profile, data, kwargs = entry.host_calls[0]
    assert profile == "rw" and data == screen.shell_data_dir()
    assert kwargs["root"] == screen.APP_DIR / "ui" and kwargs["page"] == screen.PAGE
    assert kwargs["title"] == "이적"
    assert "on_fallback" not in kwargs and callable(kwargs["before_exit"])
    assert kwargs["version"] == ca.CURRENT_VERSION


@pytest.mark.parametrize("code", [0, 20, 7])
@pytest.mark.parametrize("arguments", [[], ["--new-screen"], ["--old-screen"]])
def test_update_gate_returns_before_any_shell_or_gui(entry, code, arguments):
    entry.gate_result = code
    assert ca.main(arguments) == code
    assert entry.events == ["begin", "startup_gate"]
    assert entry.gate_arguments == arguments
    assert not entry.host_calls and not entry.releases
    assert len(entry.refusals) == (1 if code == 20 else 0)


@pytest.mark.parametrize("code", [0, 17])
def test_product_mode_returns_before_any_shell_or_gui(entry, code):
    entry.product_result = code
    assert ca.main(["--new-screen"]) == code
    assert entry.events == ["begin", "startup_gate", "dispatch_product_mode"]
    assert not entry.host_calls and not entry.releases


@pytest.mark.parametrize("arguments,code", [(["--new-screen", "--help"], 0),
                                           (["--new-screen", "--data-root"], 2)])
def test_parser_exit_keeps_its_existing_code_without_attaching(entry, arguments, code):
    with pytest.raises(SystemExit) as caught:
        ca.main(arguments)
    assert caught.value.code == code
    assert entry.failures == [caught.value]
    assert "attach_owner" not in entry.events and not entry.releases
    assert not entry.refusals


@pytest.mark.parametrize("kind", ["generation", "data_root"])
def test_gui_refusal_uses_the_existing_notice_and_fails_owner_once(entry, monkeypatch, kind):
    def refused(**_kwargs):
        entry.events.append("prepare")
        if kind == "generation":
            raise ca.DataGenerationBlocked({"status": "REFUSE", "safe": False})
        raise ca.DataRootUnavailableError()

    monkeypatch.setattr(ca, "_prepare_gui_startup", refused)
    assert ca.main(["--new-screen"]) == 1
    assert len(entry.refusals) == 1 and len(entry.failures) == 1
    assert isinstance(entry.failures[0], screen.CaStartupRefused)
    assert entry.failures[0].code == 1
    assert "attach_owner" not in entry.events and "app.run" not in entry.events
    assert "request_exit" not in entry.events and not entry.releases


@pytest.mark.parametrize("code", [None, 23])
def test_prepare_without_an_app_keeps_its_existing_return_value(entry, monkeypatch, code):
    monkeypatch.setattr(ca, "_prepare_gui_startup", lambda **_kwargs: code)
    assert ca.main(["--new-screen"]) == code
    assert len(entry.failures) == 1 and entry.failures[0].code == code
    assert "attach_owner" not in entry.events and not entry.releases


def test_pre_attach_refusal_keeps_the_existing_tk_notice(entry, monkeypatch):
    notices, destroyed = [], []

    class NoticeRoot:
        def title(self, _title):
            pass

        def resizable(self, *_args):
            pass

        def protocol(self, *_args):
            pass

        def mainloop(self):
            notices.append(True)

        def destroy(self):
            destroyed.append(True)

    def prepare(**_kwargs):
        raise ca.DataGenerationBlocked({"status": "REFUSE", "safe": False})

    with monkeypatch.context() as patch:
        patch.setattr(ca, "_prepare_gui_startup", prepare)
        patch.setattr(ca, "_startup_refusal", entry.existing_refusal)
        patch.setattr(ca, "_startup_check_observe",
                      lambda action, *_args, **kwargs: action == "finish" and kwargs.get("refused", False))
        patch.setattr(ca.tk, "Tk", NoticeRoot)
        for name in ("Label", "Button"):
            patch.setattr(ca.tk, name, lambda *_args, **_kwargs: SimpleNamespace(pack=lambda **_kw: None))
        assert ca.main(["--new-screen"]) == 1
    assert notices == [True] and destroyed == [True]
    assert len(entry.failures) == 1 and "attach_owner" not in entry.events


@pytest.mark.parametrize("code", [
    "WRITER_GATE_ABANDONED", "WRITER_GATE_TIMEOUT", "ACTIVE_WRITER_FENCE",
    "WRITER_EXIT_CLOSED", "WRITER_MUTEX_WAIT_FAILED",
])
def test_only_abandoned_writer_gate_requests_one_more_open(entry, monkeypatch, code):
    from startup_check_report import NOTICE
    from writer_session_fence import WriterFencedError

    failure = WriterFencedError(code, "fixture writer refusal")
    notices, observations, destroyed = [], [], []

    class NoticeRoot:
        def title(self, _title):
            pass

        def resizable(self, *_args):
            pass

        def protocol(self, *_args):
            pass

        def mainloop(self):
            pass

        def destroy(self):
            destroyed.append(True)

    def refuse(_arguments):
        raise failure

    def observe(action, *args, **kwargs):
        observations.append((action, args, kwargs))
        return action == "finish" and kwargs.get("refused", False)

    def label(_root, *, text, **_kwargs):
        notices.append(text)
        return SimpleNamespace(pack=lambda **_kw: None)

    with monkeypatch.context() as patch:
        patch.setattr(ca, "_run_application_main", refuse)
        patch.setattr(ca, "_startup_refusal", entry.existing_refusal)
        patch.setattr(ca, "_startup_check_observe", observe)
        patch.setattr(ca.tk, "Tk", NoticeRoot)
        patch.setattr(ca.tk, "Label", label)
        patch.setattr(ca.tk, "Button", lambda *_args, **_kwargs: SimpleNamespace(pack=lambda **_kw: None))
        with pytest.raises(WriterFencedError) as caught:
            ca.main([])
    expected = "이적 다시 열기 — 한 번 더 여세요" if code == "WRITER_GATE_ABANDONED" else NOTICE
    assert notices == [expected] and destroyed == [True]
    assert caught.value is failure and caught.value.code == code
    reason = "DEPLOY_FENCE" if code in {"WRITER_GATE_TIMEOUT", "ACTIVE_WRITER_FENCE"} else "UNKNOWN_DEPLOY_FENCE"
    assert observations == [
        ("begin", (ca.CURRENT_VERSION,), {"enabled": True}),
        ("finish", (reason,), {"refused": True, "failed": False}),
        ("finish", (), {}),
    ]


def test_unconfirmed_startup_report_keeps_the_existing_messagebox_fallback(entry, monkeypatch):
    messages = []
    blocked = ca.DataGenerationBlocked({"status": "REFUSE", "safe": False})

    def prepare(**_kwargs):
        raise blocked

    with monkeypatch.context() as patch:
        patch.setattr(ca, "_prepare_gui_startup", prepare)
        patch.setattr(ca, "_startup_refusal", lambda *_args, **_kwargs: False)
        patch.setattr(ca.messagebox, "showerror", lambda _title, message: messages.append(message))
        assert ca.main(["--new-screen"]) == 1
    assert messages == [blocked.user_message]
    assert len(entry.failures) == 1 and "attach_owner" not in entry.events


def test_instance_lock_refusal_keeps_its_existing_warning_before_attach(entry, monkeypatch):
    notices = []

    def prepare(**_kwargs):
        ca.messagebox.showwarning("already running", "existing warning")
        return None

    with monkeypatch.context() as patch:
        patch.setattr(ca, "_prepare_gui_startup", prepare)
        patch.setattr(ca.messagebox, "showwarning", lambda *args: notices.append(args))
        assert ca.main(["--new-screen"]) is None
    assert notices == [("already running", "existing warning")]
    assert len(entry.failures) == 1 and entry.failures[0].code is None
    assert "attach_owner" not in entry.events


@pytest.mark.parametrize("where", ["prepare", "run"])
def test_exceptions_restore_names_and_keep_the_original_error(entry, monkeypatch, where):
    error = ValueError("startup failure")

    def fail(*_args, **_kwargs):
        raise error

    if where == "prepare":
        monkeypatch.setattr(ca, "_prepare_gui_startup", fail)
    else:
        entry.app.run = fail
    with pytest.raises(ValueError) as caught:
        ca.main(["--new-screen"])
    assert caught.value is error
    assert entry.releases == ([] if where == "prepare" else [True])
    assert entry.failures == ([error] if where == "prepare" else [])
    assert ("request_exit" in entry.events) == (where == "run")


def test_closed_shell_uses_the_existing_confirmed_close_path(entry):
    answers = iter([True, False])
    entry.bridge.pump = lambda: next(answers)

    def run():
        entry.events.append("app.run")
        pump = next(callback for delay, callback in entry.callbacks
                    if delay == 10 and callback.__name__ == "pump")
        pump()
        pump()

    entry.app.run = run
    assert ca.main(["--new-screen"]) == 0
    assert ("closing", {"_confirmed": True}) in entry.events
    assert entry.releases == [True] and entry.events[-1] == "request_exit"


def test_owner_thread_error_is_raised_on_the_main_thread(entry, monkeypatch):
    error = ValueError("owner failure")

    def run():
        raise error

    def run_app(_profile, _data, **kwargs):
        owner = Thread(target=kwargs["owner_main"], args=(entry.bridge,))
        owner.start()
        owner.join(5)
        assert not owner.is_alive()
        return 0

    entry.app.run = run
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=run_app))
    with pytest.raises(ValueError) as caught:
        ca.main(["--new-screen"])
    assert caught.value is error and entry.releases == [True]
    assert "request_exit" in entry.events


def test_owner_thread_keeps_the_existing_startup_observation_identity(entry, monkeypatch):
    import startup_check_report as report

    identities = []
    original_gate = updates.startup_gate

    def gate(*args):
        result = original_gate(*args)
        report.release_identity({"version": ca.CURRENT_VERSION, "build_id": "probe-build"})
        return result

    def observe(action, *args, **kwargs):
        result = report.observe(action, *args, **kwargs)
        if action == "gui_identity":
            identities.append(result)
        return result

    def run_app(_profile, _data, **kwargs):
        owner = Thread(target=kwargs["owner_main"], args=(entry.bridge,))
        owner.start()
        owner.join(5)
        assert not owner.is_alive()
        return 99

    monkeypatch.setattr(updates, "startup_gate", gate)
    monkeypatch.setattr(report, "publish", lambda *_args, **_kwargs: False)
    with monkeypatch.context() as patch:
        patch.setattr(ca, "_startup_check_observe", observe)
        patch.setitem(sys.modules, "host", SimpleNamespace(run_app=run_app))
        assert ca.main(["--new-screen"]) == 0
    assert identities == [(ca.CURRENT_VERSION, "probe-build")]
    assert entry.releases == [True]


@pytest.mark.parametrize("stop", [False, True])
def test_new_screen_keeps_existing_trial_readiness_and_stop(entry, monkeypatch, stop):
    published = []
    monkeypatch.setattr(updates, "trial_context", lambda _root: object())
    monkeypatch.setattr(updates, "trial_stop_requested", lambda _root: stop)
    monkeypatch.setattr(updates, "publish_gui_ready", lambda _root: published.append(True) or True)

    def run():
        entry.events.append("app.run")
        entry.readiness = next(callback for delay, callback in entry.callbacks if delay == 0)
        entry.readiness()

    entry.app.run = run
    assert ca.main(["--new-screen"]) == 0
    assert "withdraw" in entry.events and "deiconify" not in entry.events
    assert published == ([] if stop else [True])
    assert ("finalize" in entry.events) == stop
    assert any(delay == 250 and callback is entry.readiness
               for delay, callback in entry.callbacks) == (not stop)
    assert entry.releases == [True]


def test_successful_owner_value_is_returned_instead_of_the_shell_value(entry, monkeypatch):
    def gui(_arguments):
        ca.CA_SCREEN_HOST["run"](entry.app)
        return 7

    monkeypatch.setattr(ca, "_run_gui_application", gui)
    assert ca.main(["--new-screen"]) == 7
    assert not entry.failures


def test_owner_uses_the_launched_module_and_restores_it(entry):
    host = {"requested": True, "active": False, "run": None}
    names = {name: object() for name in ("messagebox", "simpledialog", "filedialog")}
    original_tk = object()
    original_refusal = object()
    module = SimpleNamespace(CURRENT_VERSION=ca.CURRENT_VERSION, CA_SCREEN_HOST=host, tk=SimpleNamespace(Tk=original_tk),
                             _startup_refusal=original_refusal, **names)

    def gui(arguments):
        assert arguments == ["--new-screen"] and screen.ca is module
        assert host["active"] and module.tk.Tk is screen._HiddenTk
        assert isinstance(module.messagebox, screen.ScreenDialogs)
        return 31

    module._run_gui_application = gui
    assert screen.screen_runner(module)(["--new-screen"]) == 31
    assert len(entry.failures) == 1 and entry.failures[0].code == 31
    assert "attach_owner" not in entry.events
    assert host == {"requested": False, "active": False, "run": None}
    assert module.tk.Tk is original_tk
    assert module._startup_refusal is original_refusal
    assert all(getattr(module, name) is value for name, value in names.items())


class _SurfaceEvent:
    def __init__(self):
        self.event, self.callbacks = Event(), []

    def __iadd__(self, callback):
        self.callbacks.append(callback)
        return self

    def set(self):
        self.event.set()
        for callback in self.callbacks:
            callback()

    def is_set(self):
        return self.event.is_set()

    def wait(self, timeout=None):
        return self.event.wait(timeout)


def _surface(webview, *, stuck=False, unknown=False):
    window = SimpleNamespace(uid=object(), gui=None)
    window.events = SimpleNamespace(**{name: _SurfaceEvent() for name in
        ("shown", "closed", "closing", "before_load", "loaded")})
    forms = {window.uid: window}
    window.gui = object() if unknown else SimpleNamespace(BrowserView=SimpleNamespace(instances=forms))
    def destroy():
        if stuck:
            return
        forms.pop(window.uid, None)
        if window in webview.windows:
            webview.windows.remove(window)
        window.events.closed.set()
    window.destroy = destroy
    window._callbacks = {}
    webview.windows.append(window)
    return window


def _observe_fallbacks(entry, monkeypatch):
    records, legacy = [], []
    original_observe, original_gui = ca._startup_check_observe, ca._run_gui_application
    def observe(action, *args, **kwargs):
        if action in ("note", "publish"):
            records.append((action, args))
        return original_observe(action, *args, **kwargs)
    def gui(arguments):
        if not ca.CA_SCREEN_HOST["active"]:
            legacy.append(list(arguments))
        return original_gui(arguments)
    monkeypatch.setattr(ca, "_startup_check_observe", observe)
    monkeypatch.setattr(ca, "_run_gui_application", gui)
    return records, legacy


@pytest.mark.parametrize("kind,reason", [
    ("webview_import", "SHELL_IMPORT_FAILED"), ("shell_ready", "SHELL_READY_FAILED"),
    ("data_folder", "SHELL_DATA_REFUSED"),
])
@pytest.mark.parametrize("arguments", [[], ["--new-screen"]])
def test_previsible_unavailable_falls_back_once_with_one_public_record(entry, monkeypatch, tmp_path, kind, reason, arguments):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    if kind == "shell_ready":
        def unavailable():
            raise ScreenStartupUnavailable(reason)
        monkeypatch.setattr(screen, "_check_screen_ready", unavailable)
    elif kind == "webview_import":
        monkeypatch.setitem(sys.modules, "webview", None)
    else:
        def unavailable(*args, **kwargs):
            raise PermissionError(str(tmp_path))
        monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=unavailable))
    assert ca.main(arguments) == 0
    assert legacy == [arguments] and entry.releases == [True]
    code = reason if reason == "SHELL_IMPORT_FAILED" else "SCREEN_UNAVAILABLE_FALLBACK_OLD_" + reason
    assert records == [("note", (code,)), ("publish", ())]
    assert all(str(tmp_path) not in str(item) for item in records)
    assert not ca.CA_SCREEN_HOST["active"] and not getattr(sys.modules.get("webview"), "windows", [])


def test_startup_refusal_never_falls_back(entry, monkeypatch):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    def refused(*args, **kwargs):
        raise screen.CaStartupRefused(23)
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=refused))
    assert ca.main([]) == 23
    assert not legacy and not records and not entry.releases


@pytest.mark.parametrize("kind", ["writer", "data", "unknown_data"])
def test_intentional_guard_error_never_falls_back(entry, monkeypatch, kind):
    from writer_session_fence import WriterFencedError
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    error = WriterFencedError("WRITER_GATE_TIMEOUT", "writer gate") if kind == "writer" else (
        ca.DataRootUnavailableError() if kind == "data" else ca.DataGenerationBlocked({"status": "UNKNOWN", "safe": False}))
    def refused(*args, **kwargs):
        raise error
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=refused))
    with pytest.raises(type(error)) as caught:
        ca.main([])
    assert caught.value is error and not legacy and not records


@pytest.mark.parametrize("marker", ["ready", "shown"])
def test_seen_surface_never_falls_back(entry, monkeypatch, marker):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    error = RuntimeError("screen failed")
    webview = sys.modules["webview"]
    if marker == "shown":
        webview.create_window = lambda: _surface(webview)
    def failed(*args, **kwargs):
        if marker == "ready":
            kwargs["owner_main"](entry.bridge)
        else:
            webview.create_window().events.shown.set()
        raise error
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=failed))
    with pytest.raises(RuntimeError) as caught:
        ca.main([])
    assert caught.value is error and not legacy and not records


def test_unknown_owner_cleanup_never_opens_old_screen(entry, monkeypatch):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    entry.bridge.attach_owner = lambda processor: entry.events.append("attach_owner")
    entry.app._application_close_complete = False
    entry.app._loop_cleanup_finished = False
    error = RuntimeError("screen failed before readiness")
    def failed(*args, **kwargs):
        kwargs["owner_main"](entry.bridge)
        raise error
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=failed))
    with pytest.raises(RuntimeError) as caught:
        ca.main([])
    assert caught.value is error and not legacy and not records


@pytest.mark.parametrize("unknown", [False, True])
def test_live_or_unknown_form_blocks_fallback(entry, monkeypatch, unknown):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    webview = sys.modules["webview"]
    webview.create_window = lambda: _surface(webview, stuck=True, unknown=unknown)
    error = RuntimeError("previsible screen failed")
    def failed(*args, **kwargs):
        webview.create_window()
        raise error
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=failed))
    with pytest.raises(RuntimeError) as caught:
        ca.main([])
    assert caught.value is error and not legacy and not records


def test_created_previsible_form_never_allows_same_process_legacy_window(entry, monkeypatch):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    webview = sys.modules["webview"]
    created = []
    def create():
        window = _surface(webview)
        created.append(window)
        return window
    webview.create_window = create
    def failed(*args, **kwargs):
        webview.create_window()
        raise RuntimeError("previsible screen failed")
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=failed))
    with pytest.raises(RuntimeError):
        ca.main([])
    assert legacy == [] and len(created) == 1
    assert not records and len(webview.windows) == 1


def test_fallback_record_failure_keeps_work_running(entry, monkeypatch):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    observer = ca._startup_check_observe
    def failed_record(action, *args, **kwargs):
        result = observer(action, *args, **kwargs)
        if action == "publish":
            raise OSError("record unavailable")
        return result
    monkeypatch.setattr(ca, "_startup_check_observe", failed_record)
    monkeypatch.setitem(sys.modules, "webview", None)
    assert ca.main([]) == 0 and legacy == [[]]
    assert len(records) == 2


def test_next_start_tries_screen_again_and_never_retries_within_one_start(entry, monkeypatch):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    attempts = []
    def failed(*args, **kwargs):
        attempts.append(True)
        raise PermissionError("screen folder unavailable")
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=failed))
    assert ca.main([]) == 0 and attempts == [True] and legacy == [[]]
    assert ca.main([]) == 0 and attempts == [True, True] and legacy == [[], []]
    assert len([item for item in records if item[0] == "note"]) == 2


def test_emergency_flag_wins_over_new_screen_alias(entry):
    assert ca.main([ca.CA_OLD_SCREEN_ARGUMENT, ca.CA_NEW_SCREEN_ARGUMENT]) == 0
    assert not entry.host_calls and entry.releases == [True]


def test_auto_update_empty_arguments_reach_default_screen(entry, monkeypatch, tmp_path):
    import subprocess
    launches = []
    def launch(command, **kwargs):
        launches.append(command)
        return SimpleNamespace(pid=1)
    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(updates, "version_bundle", lambda *_args: tmp_path)
    monkeypatch.setattr(updates, "version_manifest", lambda *_args: {"source_commit": "a" * 40})
    assert updates.launch_version(tmp_path, "a" * 40, []) == 1
    assert launches[0][4:] == []
    assert ca.main(launches[0][4:]) == 0 and len(entry.host_calls) == 1


def test_fallback_record_uses_only_approved_nonblocking_codes():
    from startup_check import startup_result
    for reason in ("WEBVIEW2_MISSING", "SHELL_READY_FAILED", "SHELL_DATA_REFUSED", "SCREEN_START_ERROR"):
        code = reason if reason == "SHELL_IMPORT_FAILED" else "SCREEN_UNAVAILABLE_FALLBACK_OLD_" + reason
        result = startup_result(reasons=[code])
        assert result["startable"] and result["reasons"] == [code]
    assert not startup_result(reasons=["SCREEN_UNAVAILABLE_FALLBACK_OLD_UNKNOWN"])["startable"]



@pytest.mark.parametrize("code", ["SHELL_DATA_IN_APP_ROOT", "SHELL_DATA_NOT_WRITABLE"])
def test_future_shell_data_refusal_uses_the_same_safe_fallback(entry, monkeypatch, code):
    records, legacy = _observe_fallbacks(entry, monkeypatch)
    def unavailable(*args, **kwargs):
        raise RuntimeError(code)
    monkeypatch.setitem(sys.modules, "host", SimpleNamespace(run_app=unavailable))
    assert ca.main([]) == 0 and legacy == [[]]
    assert records == [("note", ("SCREEN_UNAVAILABLE_FALLBACK_OLD_SHELL_DATA_REFUSED",)), ("publish", ())]


def test_restart_exit_waits_for_isolated_durable_write_and_mutex_release(entry, monkeypatch, tmp_path):
    import sqlite3
    import threading
    import writer_session_fence as fence
    entered, finish, durable = threading.Event(), threading.Event(), threading.Event()
    monkeypatch.setattr(fence, '_WRITER_EXIT_CLOSED', False)
    database = tmp_path / 'durable.sqlite3'
    failures = []
    def writing():
        try:
            with fence.writer_admission('screen_fallback_save'):
                with sqlite3.connect(database) as connection:
                    connection.execute('CREATE TABLE saved (value INTEGER)')
                    connection.execute('INSERT INTO saved VALUES (1)')
                    entered.set()
                    assert finish.wait(5)
                durable.set()
        except BaseException as error:
            failures.append(error)
            entered.set()
    writer = threading.Thread(target=writing)
    writer.start()
    def run_app(profile, data, **kwargs):
        assert entered.wait(5) and not failures
        assert kwargs['before_exit']('SHELL_START_TIMEOUT', 0) is False
        assert not durable.is_set() and not entry.releases
        finish.set()
        writer.join(5)
        assert not writer.is_alive() and not failures and durable.is_set()
        assert kwargs['before_exit']('SHELL_START_TIMEOUT', 0) is True
        mutex = fence._acquire_named_mutex(fence.writer_admission_mutex_name(fence.canonical_control_root()), 0)
        assert mutex is not None
        mutex.release()
        raise SystemExit(3)
    monkeypatch.setitem(sys.modules, 'host', SimpleNamespace(run_app=run_app))
    try:
        with pytest.raises(SystemExit) as ended:
            ca.main([])
        assert ended.value.code == 3
    finally:
        finish.set()
        writer.join(5)
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT value FROM saved').fetchall() == [(1,)]
    assert 'prepare' not in entry.events and 'deiconify' not in entry.events

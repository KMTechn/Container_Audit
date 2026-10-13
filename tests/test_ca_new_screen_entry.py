"""The new screen goes through the existing startup; all windows are fake."""
from types import SimpleNamespace
from threading import Thread
import sys

import pytest

import auto_update as updates
import Container_Audit as ca
import ca_screen_bridge as screen


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
    )

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
    yield state
    assert host == {"requested": False, "active": False, "run": None}
    assert ca.tk.Tk is original_tk and screen.ca is original_module
    assert all(getattr(ca, name) is value for name, value in original_names.items())
    assert ca._startup_refusal is refuse


def test_without_flag_runs_the_existing_gui_and_releases_its_lease(entry, monkeypatch):
    def unexpected(_module):
        pytest.fail("screen_runner called without the flag")

    monkeypatch.setattr(screen, "screen_runner", unexpected)
    original_gui = ca._run_gui_application

    def gui(arguments):
        entry.events.append("gui")
        return original_gui(arguments)

    monkeypatch.setattr(ca, "_run_gui_application", gui)
    assert ca.main([]) == 0
    assert entry.events == ["begin", "startup_gate", "dispatch_product_mode", "gui", "prepare", "app.run"]
    assert entry.releases == [True] and not entry.host_calls


def test_new_screen_keeps_gate_order_arguments_and_gui_exit_value(entry, tmp_path):
    arguments = ["--new-screen", "--data-root", str(tmp_path)]
    assert ca.main(arguments) == 0
    assert entry.events == ["begin", "startup_gate", "dispatch_product_mode", "run_app",
                            "prepare", "attach_owner", "app.run", "request_exit"]
    assert entry.gate_arguments == arguments and entry.data_root == str(tmp_path)
    assert entry.releases == [True]
    profile, data, kwargs = entry.host_calls[0]
    assert profile == "rw" and data == screen.shell_data_dir()
    assert kwargs["root"] == screen.APP_DIR / "ui" and kwargs["page"] == screen.PAGE
    assert kwargs["title"] == "이적" and "owner_timeout" not in kwargs


@pytest.mark.parametrize("code", [0, 20, 7])
def test_update_gate_returns_before_any_shell_or_gui(entry, code):
    entry.gate_result = code
    assert ca.main(["--new-screen"]) == code
    assert entry.events == ["begin", "startup_gate"]
    assert entry.gate_arguments == ["--new-screen"]
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
    module = SimpleNamespace(CA_SCREEN_HOST=host, tk=SimpleNamespace(Tk=original_tk),
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

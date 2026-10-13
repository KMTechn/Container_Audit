import importlib
from pathlib import Path
import sys
from threading import Event, get_ident
from types import SimpleNamespace

import pytest

from tests.test_ca_screen_bridge import _Pedal, _Sound


@pytest.fixture
def closing_bridge(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "shell"))
    host = importlib.import_module("host")
    entered, release, exited = Event(), Event(), Event()
    calls = []
    answer = [True]

    class Processor:
        def state(self):
            return {}

        def closing(self):
            calls.append(get_ident())
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test closing was not released")
            return answer[0]

    bridge = host.Bridge(tmp_path, "rw", processor_factory=Processor,
                         pedal=_Pedal(), sound=_Sound())
    bridge.set_exit_handler(exited.set)
    yield SimpleNamespace(host=host, bridge=bridge, entered=entered,
                          release=release, exited=exited, calls=calls, answer=answer)
    release.set()
    bridge.close()


def test_slow_x_retains_one_owner_question(closing_bridge):
    case = closing_bridge
    assert case.bridge.ask_closing(timeout=0.01) is None
    assert case.entered.is_set()
    pending = case.bridge._closing_future
    assert not pending.done()
    assert case.bridge.ask_closing(timeout=0.01) is None
    assert case.bridge._closing_future is pending
    assert case.calls == [case.bridge.owner_thread_id]
    case.release.set()
    assert pending.result(timeout=2) is True


@pytest.mark.parametrize("allowed", [True, False])
def test_late_owner_answer_cancels_x_and_resolves_the_waiting_strip(closing_bridge, allowed):
    case = closing_bridge
    modes, hidden = [], Event()
    case.answer[0] = allowed

    def show(mode):
        modes.append(mode)
        if mode is None:
            hidden.set()

    waiting = case.host.ClosingWait(case.bridge, show, timeout=5)
    try:
        assert waiting.closing() is False
        assert modes == ["waiting"]
        assert not case.exited.is_set()
        assert waiting.closing() is False
        assert case.calls == [case.bridge.owner_thread_id]
        case.release.set()
        if allowed:
            assert case.exited.wait(2)
            assert modes == ["waiting"]
        else:
            assert hidden.wait(2)
            assert modes == ["waiting", None]
            assert not case.bridge._exit_requested
            assert not case.exited.is_set()
        assert not waiting.forced
    finally:
        waiting.close()


def test_closing_timeout_offers_wait_without_repeating_the_owner_question(closing_bridge):
    case = closing_bridge
    choices, modes = Event(), []

    def show(mode):
        modes.append(mode)
        if mode == "choice":
            choices.set()

    waiting = case.host.ClosingWait(case.bridge, show, timeout=0.05)
    try:
        assert waiting.closing() is False
        assert choices.wait(2)
        assert not case.exited.is_set()
        pending = case.bridge._closing_future
        choices.clear()
        waiting.choose("wait")
        assert modes[-1] == "waiting"
        assert choices.wait(2)
        assert modes == ["waiting", "choice", "waiting", "choice"]
        assert case.bridge._closing_future is pending
        assert case.calls == [case.bridge.owner_thread_id]
        assert not waiting.forced
        case.release.set()
        assert case.exited.wait(2)
    finally:
        waiting.close()


def test_native_closing_strip_warns_and_defaults_to_wait(closing_bridge, monkeypatch, tmp_path):
    class Controls(list):
        def Add(self, value):
            self.append(value)

        def Remove(self, value):
            self.remove(value)

    class Click:
        def __iadd__(self, callback):
            self.callback = callback
            return self

    class Control:
        def __init__(self):
            self.Controls = Controls()
            self.Click = Click()
            self.focused = False
            self.disposed = False
            self.ContainsFocus = False

        def BringToFront(self):
            pass

        def Focus(self):
            self.focused = True

        def Dispose(self):
            self.disposed = True

    monkeypatch.setitem(sys.modules, "System", SimpleNamespace(Action=lambda callback: callback))
    monkeypatch.setitem(sys.modules, "System.Windows.Forms", SimpleNamespace(
        Button=Control, FlowLayoutPanel=Control, Label=Control,
        DockStyle=SimpleNamespace(Top="top"), Padding=lambda *args: args))
    monkeypatch.setitem(sys.modules, "System.Drawing", SimpleNamespace(Font=lambda *args: args))
    browser = Control()
    form = SimpleNamespace(IsDisposed=False, Controls=Controls(),
                           BeginInvoke=lambda callback: callback(),
                           browser=SimpleNamespace(webview=browser))
    native = closing_bridge.host.NativeHost(SimpleNamespace(native=form), closing_bridge.bridge, tmp_path)
    actions = []
    native.show_closing("waiting", actions.append)
    panel, label, close, wait = native._closing_banner
    assert label.Text == "끝내는 중 — 남은 일을 마치고 닫습니다"
    assert not close.Visible and not wait.Visible
    native.show_closing("choice", actions.append)
    assert label.Text == "응답이 없습니다 —\n그래도 닫으면 저장 중인 것은 잃을 수 있습니다"
    assert close.Visible and wait.Visible
    assert close.Text == "그래도 닫기" and wait.Text == "더 기다리기"
    assert close.TabStop and wait.TabStop
    assert (close.TabIndex, wait.TabIndex) == (0, 1)
    assert wait.focused and not close.focused
    wait.Click.callback(None, None)
    close.Click.callback(None, None)
    assert actions == ["wait", "close"]
    panel.ContainsFocus = True
    native.show_closing(None, actions.append)
    assert native._closing_banner is None
    assert panel.disposed and panel not in form.Controls
    assert browser.focused

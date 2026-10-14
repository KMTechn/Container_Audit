"""Real, immediately withdrawn Tk Button.invoke boundary; no visible window."""
from types import SimpleNamespace
import tkinter as tk

import pytest

import Container_Audit as ca
from ca_screen_bridge import CaProcessor
from tk_callback_result import bind_button_callback

pytestmark = [pytest.mark.real_gui, pytest.mark.iwrun_real_window("Tk.withdraw")]


@pytest.fixture(scope="module")
def withdrawn_tk():
    # This narrow SPEC 18:30 exception uses the original Tk class underneath
    # the host's constructor guard. Withdraw before Tk's Python initialization
    # can process a mapping event; no event loop, deiconify or Toplevel is used.
    real_tk = next(base for base in tk.Tk.__mro__ if base.__module__ == "tkinter" and base.__name__ == "Tk")
    class WithdrawnTk(real_tk):
        def _loadtk(self):
            self.tk.call("wm", "withdraw", ".")
            super()._loadtk()
    root = WithdrawnTk()
    root.withdraw()
    assert root.state() == "withdrawn" and not root.winfo_ismapped()
    errors = []
    root.report_callback_exception = lambda *error: errors.append(error[0])
    try:
        yield root
        assert errors == []
        assert root.state() == "withdrawn" and not root.winfo_ismapped()
        assert all(not child.winfo_ismapped() for child in root.winfo_children())
    finally:
        root.destroy()


@pytest.mark.parametrize("outcome", ["success", "failure", "unknown", "error_text"])
def test_actual_tk_button_invoke_preserves_python_operation_return(withdrawn_tk, outcome):
    value = {"success": True, "failure": False, "unknown": None, "error_text": "operation-error"}[outcome]
    button = bind_button_callback(tk.Button(withdrawn_tk), lambda: value)
    if type(value) is bool:
        assert type(button.invoke()) is not bool
    app = SimpleNamespace(park_button=button)
    reply = CaProcessor(app)._invoke("park_button")
    assert reply["ok"] is (outcome == "success")
    if outcome != "success":
        assert reply["result"]["kind"] == ("idle" if outcome == "unknown" else "warn")
    assert button._ca_callback_result.executed
    assert button._ca_callback_result.value is value


def test_actual_tk_disabled_button_cannot_reuse_a_previous_success(withdrawn_tk):
    button = bind_button_callback(tk.Button(withdrawn_tk), lambda: True)
    processor = CaProcessor(SimpleNamespace(park_button=button))
    assert processor._invoke("park_button")["ok"] is True
    # Bridge admission remains enabled; the actual Tcl widget refuses execution.
    original = button.invoke
    def disabled_invoke():
        button.configure(state=tk.DISABLED)
        return original()
    button.invoke = disabled_invoke
    reply = processor._invoke("park_button")
    assert reply["ok"] is False and reply["result"]["kind"] == "idle"
    assert not button._ca_callback_result.executed


def test_actual_tk_updated_submit_command_uses_the_new_python_result(withdrawn_tk):
    button = bind_button_callback(tk.Button(withdrawn_tk), lambda: True)
    app = ca.ContainerAudit.__new__(ca.ContainerAudit)
    app.submit_tray_button = button
    processor = CaProcessor(app)
    assert processor._invoke("submit_tray_button")["ok"] is True
    app._configure_widget_options(button, command=lambda: False)
    reply = processor._invoke("submit_tray_button")
    assert reply["ok"] is False and reply["result"]["kind"] == "warn"


def test_actual_tk_unwrapped_callback_result_is_unknown_even_when_tcl_is_truthy(withdrawn_tk):
    button = tk.Button(withdrawn_tk, command=lambda: True)
    reply = CaProcessor(SimpleNamespace(park_button=button))._invoke("park_button")
    assert reply["ok"] is False and reply["result"]["kind"] == "idle"

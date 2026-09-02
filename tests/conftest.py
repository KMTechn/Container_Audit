import os
import sys
import tkinter
from tkinter import messagebox, simpledialog

import pytest


# Automated GUI/contract runs must never reach the operator's audio device.
os.environ.setdefault("SDL_AUDIODRIVER", "dummy")
os.environ.setdefault("PYGAME_HIDE_SUPPORT_PROMPT", "1")
os.environ.setdefault("KMTECH_TEST_SILENT_AUDIO", "1")


class HeadlessGuiInvocationError(RuntimeError):
    """A test reached a real Tk window or modal-dialog entry point."""


def _blocked_gui_call(entry_point):
    def blocked(*_args, **_kwargs):
        raise HeadlessGuiInvocationError(
            f"headless test attempted real GUI entry point: {entry_point}"
        )

    return blocked


_MESSAGEBOX_ENTRY_POINTS = (
    "Message",
    "showinfo",
    "showwarning",
    "showerror",
    "askquestion",
    "askokcancel",
    "askyesno",
    "askyesnocancel",
    "askretrycancel",
)
_SIMPLEDIALOG_ENTRY_POINTS = (
    "askstring",
    "askinteger",
    "askfloat",
    "Dialog",
    "SimpleDialog",
)


@pytest.fixture(autouse=True)
def fail_fast_on_real_gui(monkeypatch, request):
    """Keep every ordinary test headless, including imported module aliases."""

    if request.node.get_closest_marker("real_gui") is not None:
        pytest.skip("real GUI tests are disabled on this headless host")

    for name in _MESSAGEBOX_ENTRY_POINTS:
        if hasattr(messagebox, name):
            monkeypatch.setattr(
                messagebox,
                name,
                _blocked_gui_call(f"tkinter.messagebox.{name}"),
            )
    for name in _SIMPLEDIALOG_ENTRY_POINTS:
        if hasattr(simpledialog, name):
            monkeypatch.setattr(
                simpledialog,
                name,
                _blocked_gui_call(f"tkinter.simpledialog.{name}"),
            )
    monkeypatch.setattr(
        tkinter,
        "Toplevel",
        _blocked_gui_call("tkinter.Toplevel"),
    )
    monkeypatch.setattr(
        tkinter,
        "Tk",
        _blocked_gui_call("tkinter.Tk"),
    )

    container_module = sys.modules.get("Container_Audit")
    if container_module is not None:
        bound_messagebox = getattr(container_module, "messagebox", None)
        for name in _MESSAGEBOX_ENTRY_POINTS:
            if bound_messagebox is not None and hasattr(bound_messagebox, name):
                monkeypatch.setattr(
                    bound_messagebox,
                    name,
                    _blocked_gui_call(f"Container_Audit.messagebox.{name}"),
                )
        bound_simpledialog = getattr(container_module, "simpledialog", None)
        for name in _SIMPLEDIALOG_ENTRY_POINTS:
            if bound_simpledialog is not None and hasattr(bound_simpledialog, name):
                monkeypatch.setattr(
                    bound_simpledialog,
                    name,
                    _blocked_gui_call(f"Container_Audit.simpledialog.{name}"),
                )
        bound_tk = getattr(container_module, "tk", None)
        if bound_tk is not None:
            monkeypatch.setattr(
                bound_tk,
                "Toplevel",
                _blocked_gui_call("Container_Audit.tk.Toplevel"),
            )
            monkeypatch.setattr(
                bound_tk,
                "Tk",
                _blocked_gui_call("Container_Audit.tk.Tk"),
            )


@pytest.fixture
def headless_gui_error_type():
    return HeadlessGuiInvocationError

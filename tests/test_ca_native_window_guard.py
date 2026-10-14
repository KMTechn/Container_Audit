"""Negative controls for the native window seam; no interactive call is executed."""
import ast
import ctypes
import inspect
from pathlib import Path

import pytest
import runtime_instance_win32 as native

ROOT = Path(__file__).resolve().parents[1]


def test_native_window_defaults_record_without_loading_user32(native_window_calls, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("a record-only request loaded a native DLL")
    monkeypatch.setattr(ctypes, "WinDLL", fail)
    assert native.visible_top_level_windows(1234) == []
    native.activate_window(42)
    native.timed_notice("isolated notice", "이적", 0, 5000)
    native.position_window_absolute(42, -100, 20)
    assert [row[0] for row in native_window_calls] == [
        "visible_top_level_windows", "activate_window", "timed_notice", "position_window_absolute"]


@pytest.mark.parametrize("api", ["MessageBoxTimeoutW", "SetForegroundWindow", "FlashWindowEx"])
def test_bypassing_native_seam_cannot_call_a_real_window(api):
    for library in (ctypes.WinDLL("user32", use_last_error=True), ctypes.windll.user32):
        with pytest.raises(AssertionError):
            getattr(library, api)(None)


def test_removing_default_stub_still_cannot_display_notice():
    with pytest.raises(AssertionError):
        inspect.unwrap(native.timed_notice)("isolated notice", "이적")


def test_window_search_default_records_without_enumwindows(native_window_calls, monkeypatch):
    def forbidden_loader(*args, **kwargs):
        raise AssertionError('window search loaded user32')
    monkeypatch.setattr(ctypes, 'WinDLL', forbidden_loader)
    assert native.visible_top_level_windows(4242) == []
    assert native_window_calls == [('visible_top_level_windows', (4242,), {})]


@pytest.mark.parametrize('loader', ('WinDLL', 'windll', 'absolute'))
def test_direct_enumwindows_is_blocked(loader):
    library = (ctypes.windll.user32 if loader == 'windll' else
               ctypes.WinDLL('C:/Windows/System32/user32.dll' if loader == 'absolute' else 'user32'))
    with pytest.raises(AssertionError):
        library.EnumWindows(None, 0)


def test_unwrapped_window_search_cannot_reach_enumwindows():
    with pytest.raises(AssertionError):
        inspect.unwrap(native.visible_top_level_windows)(4242)


def test_window_actions_have_no_direct_ctypes_call_outside_native_seam():
    actions = {"MessageBoxTimeoutW", "MessageBoxW", "SetForegroundWindow", "FlashWindowEx",
               "ShowWindow", "SetWindowPos", "SetFocus", "BringWindowToTop", "EnumWindows"}
    excluded = {"runtime_instance_win32.py"}
    violations = []
    for path in [*ROOT.glob("*.py"), *ROOT.joinpath("tools").glob("*.py")]:
        if path.name in excluded:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        if not any(isinstance(node, ast.Import) and any(alias.name == "ctypes" for alias in node.names)
                   for node in ast.walk(tree)):
            continue
        # Manual qualification drivers use pywin32, not direct ctypes/user32.
        pywin32 = {alias.asname or alias.name for node in ast.walk(tree)
                   if isinstance(node, ast.Import) for alias in node.names if alias.name == "win32gui"}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "getattr" and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant) and node.args[1].value in actions):
                violations.append((path.name, node.lineno, "dynamic window action"))
            if isinstance(node, ast.Attribute) and node.attr in actions:
                if isinstance(node.value, ast.Name) and node.value.id in pywin32:
                    continue
                violations.append((path.name, node.lineno, node.attr))
    assert violations == []

"""Native preflight uses only dependency boundaries; creates no form."""
import sys
from types import SimpleNamespace
import pytest
import Container_Audit as ca
import ca_screen_bridge as screen
import writer_session_fence as fence
from screen_startup_fallback import ScreenStartupUnavailable
from tests.test_ca_new_screen_entry import entry
from tests.test_ca_s1_fallback import visible

_NATIVE_PREFLIGHT = screen._prepare_screen_backend


@pytest.fixture
def backend(entry, monkeypatch):
    native = _NATIVE_PREFLIGHT
    monkeypatch.setattr(screen, "_prepare_screen_backend", native)
    calls = []
    state = SimpleNamespace(renderer="edgechromium", runtime="available", error=None)
    def initialize(gui):
        calls.append(("backend", gui))
        if state.error is not None:
            raise state.error
        return state
    def runtime(folder):
        calls.append(("runtime", folder))
        return state.runtime
    sys.modules["webview"].settings = {"WEBVIEW2_RUNTIME_PATH": None}
    monkeypatch.setitem(sys.modules, "webview.guilib", SimpleNamespace(initialize=initialize))
    monkeypatch.setitem(sys.modules, "Microsoft.Web.WebView2.Core", SimpleNamespace(CoreWebView2Environment=SimpleNamespace(GetAvailableBrowserVersionString=runtime)))
    return state, calls, native


def test_backend_and_runtime_checked_after_web_allowed_before_run_app(entry, backend, monkeypatch):
    state, calls, native = backend
    original = sys.modules["host"].run_app
    def allowed(*_args, **_kwargs):
        calls.append(("allowed",))
        return True
    def run(*args, **kwargs):
        calls.append(("run_app",))
        return original(*args, **kwargs)
    monkeypatch.setattr(sys.modules["host"], "web_allowed", allowed, raising=False)
    monkeypatch.setattr(sys.modules["host"], "run_app", run)
    assert ca.main([]) == 0
    assert [item[0] for item in calls] == ["allowed", "backend", "runtime", "run_app"]
    assert entry.host_calls and not entry.failures


@pytest.mark.parametrize("fault", ["backend_exception", "other_renderer", "missing_runtime"])
def test_only_native_preparation_failure_uses_tk_before_owner_or_window(entry, visible, backend, fault):
    state, calls, native = backend
    if fault == "backend_exception":
        state.error = RuntimeError()
    elif fault == "other_renderer":
        state.renderer = "mshtml"
    else:
        state.runtime = None
    assert ca.main([]) == 0
    assert entry.host_calls == [] and entry.failures == []
    assert visible.preparations == [1] and len(entry.releases) == 1
    assert sys.modules["webview"].windows == []


@pytest.mark.parametrize("kind", ["writer", "generation", "data_root"])
def test_native_preflight_does_not_convert_intentional_refusal(entry, backend, kind):
    state, calls, native = backend
    errors = {"writer": fence.WriterFenceError("TEST_REFUSED", "refused"),
              "generation": ca.DataGenerationBlocked({"status": "REFUSE"}),
              "data_root": ca.DataRootUnavailableError("refused")}
    state.error = errors[kind]
    with pytest.raises(type(state.error)) as refused:
        native(ca)
    assert refused.value is state.error
    assert not entry.host_calls


def test_active_shell_fallback_skips_native_preflight(entry, backend, monkeypatch):
    state, calls, native = backend
    monkeypatch.setattr(sys.modules["host"], "web_allowed", lambda *_args, **_kwargs: False, raising=False)
    assert ca.main([]) == 0
    assert calls == [] and not entry.host_calls


def test_native_preparation_creates_no_recovery_marker(entry, backend, tmp_path, monkeypatch):
    state, calls, native = backend
    state.error = OSError()
    data = tmp_path / "screen"
    monkeypatch.setattr(screen, "shell_data_dir", lambda: data)
    assert ca.main([]) == 0
    assert not data.exists() and not entry.host_calls

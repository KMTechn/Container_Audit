import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import tempfile
import time
import tkinter
from tkinter import messagebox, simpledialog

import pytest
from tests.native_widgets import native_tk_interpreter


def pytest_addoption(parser):
    parser.addoption(
        "--native-e-root", default=None,
        help="Explicit owned directory for tests of the unchanged native E-drive policy",
    )


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    """Own mutable state before collection, including every child interpreter."""
    if os.environ.get("KMTECH_TEST_CA_TASK_ROOT"):
        from tests.sitecustomize import install_write_boundary
        install_write_boundary()
    if config.option.basetemp:
        Path(config.option.basetemp).resolve().parent.mkdir(parents=True, exist_ok=True)
    base = config._tmp_path_factory.getbasetemp()
    patch = pytest.MonkeyPatch()
    config.add_cleanup(patch.undo)
    _isolate_environment(base / "session", patch)


def pytest_sessionfinish(session, exitstatus):
    configured = os.environ.get("KMTECH_TEST_CA_TASK_ROOT")
    if not configured:
        return
    root = Path(configured)
    violations = root / "boundary-violations.jsonl"
    count = len(violations.read_text(encoding="utf-8").splitlines()) if violations.exists() else 0
    live = [thread.name for thread in threading.enumerate()
            if thread is not threading.main_thread()]
    (root / "isolation.json").write_text(
        json.dumps({"outside_write_attempts": count, "remaining_threads": live}, indent=2) + "\n",
        encoding="utf-8",
    )
    if count or live:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def _isolate_environment(root, patch):
    for name, directory in (
        ("LOCALAPPDATA", "local"), ("APPDATA", "roaming"),
        ("PROGRAMDATA", "program"), ("TEMP", "t"), ("TMP", "t"),
    ):
        path = root / directory
        path.mkdir(parents=True, exist_ok=True)
        patch.setenv(name, str(path))
    patch.delenv("CONTAINER_AUDIT_DATA_ROOT", raising=False)
    for name in ("CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH", "KM_LOGISTICS_PROFILE_PATH"):
        patch.delenv(name, raising=False)
    patch.setattr(tempfile, "tempdir", str(root / "t"))
    patch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    if os.name == "nt":
        modules = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/Modules"
        patch.setenv("PSModulePath", str(modules))
    patch.setenv("PSModuleAnalysisCachePath", str(root / "module-cache"))


@pytest.fixture
def tmp_path(request, tmp_path_factory):
    """Keep deliberate Unicode/space leaves without pytest's MAX_PATH-prone prefix."""
    name = hashlib.sha256(request.node.nodeid.encode("utf-8")).hexdigest()[:10]
    return tmp_path_factory.mktemp(name)


@pytest.fixture
def native_e_path(request, tmp_path):
    """Keep native drive policy coverage explicit without requiring an E drive."""
    configured = request.config.getoption("--native-e-root")
    root = Path(configured).resolve() if configured else tmp_path
    if os.name != "nt" or root.drive.casefold() != "e:":
        pytest.skip("native E-drive policy requires an owned --native-e-root on Windows")
    if not root.is_relative_to(Path("E:/KMTech")):
        pytest.skip("native release policy requires the owned root below its KMTech directory")
    if not Path(root.anchor).is_dir():
        pytest.skip("native E-drive capability is unavailable")
    if not configured:
        yield root
        return
    root.mkdir(parents=True, exist_ok=True)
    import tempfile
    with tempfile.TemporaryDirectory(prefix="native-", dir=root) as temporary:
        yield Path(temporary)


@pytest.fixture(autouse=True)
def isolate_product_state(tmp_path, monkeypatch):
    _isolate_environment(tmp_path / "s", monkeypatch)
    import writer_session_fence as fence

    root = fence.canonical_control_root()
    mutex = fence.WRITER_MUTEX_NAME + ".test." + hashlib.sha256(
        str(root).encode("utf-8")
    ).hexdigest()[:16]
    derive = fence.writer_admission_mutex_name
    acquire = fence._acquire_named_mutex

    def isolated_name(control_root, *, environ=None):
        name = derive(control_root, environ=environ)
        return mutex if name == fence.WRITER_MUTEX_NAME else name

    def guarded_acquire(name, timeout_seconds):
        if name == fence.WRITER_MUTEX_NAME:
            raise AssertionError("test attempted canonical writer-admission mutex")
        return acquire(name, timeout_seconds)

    monkeypatch.setattr(fence, "writer_admission_mutex_name", isolated_name)
    monkeypatch.setattr(fence, "_acquire_named_mutex", guarded_acquire)
    monkeypatch.setenv("KMTECH_TEST_CA_WRITER_ROOT", str(root))
    monkeypatch.setenv("KMTECH_TEST_CA_WRITER_MUTEX", mutex)
    test_dir = Path(__file__).resolve().parent
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join((str(test_dir), str(test_dir.parent))))


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
    # Explicit native widget tests own their roots and never invoke modal input.
    if request.node.get_closest_marker("real_gui") is not None:
        return
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


@pytest.fixture(autouse=True)
def owned_tk_workers(monkeypatch):
    """Drain test-owned workers even when an assertion skips the normal close."""
    from tk_serial_ui_lane import TkSerialUiLane
    from preflight_scan_hold import PreflightScanHoldWriter

    before = set(threading.enumerate())
    workers = []
    for cls, thread_attribute in ((TkSerialUiLane, "worker_thread"),
                                  (PreflightScanHoldWriter, "thread")):
        original = cls.__init__

        def initialize(instance, *args, _init=original, _thread=thread_attribute, **kwargs):
            try:
                _init(instance, *args, **kwargs)
            finally:
                if hasattr(instance, _thread):
                    workers.append((instance, getattr(instance, _thread)))

        monkeypatch.setattr(cls, "__init__", initialize)
    try:
        yield workers
    finally:
        errors = []
        deadline = time.monotonic() + 15
        while any(thread.is_alive() for _, thread in workers):
            for worker, thread in list(workers):
                if not thread.is_alive():
                    continue
                try:
                    worker.close_idle()
                    if thread.is_alive():
                        worker._pump()
                except BaseException as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")
            if time.monotonic() >= deadline:
                break
            threading.Event().wait(0.002)
        leaked = [thread.name for thread in threading.enumerate()
                  if thread not in before and not thread.daemon]
        owned_live = [thread.name for _, thread in workers if thread.is_alive()]
        assert not leaked and not owned_live, f"worker leak: {leaked + owned_live}; cleanup: {errors}"
        assert not errors, f"worker cleanup errors: {errors}"

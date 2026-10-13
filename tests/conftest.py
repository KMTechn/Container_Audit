import functools
import builtins
import importlib
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
from urllib.parse import urlsplit, urlunsplit

import pytest
from tests.native_widgets import native_tk_interpreter


_TEST_SERVER_ORIGIN = "https://unreachable.invalid"
_TEST_SERVER_DEFAULTS = {
    "current_user_onboarding": ("DEFAULT_SERVER_BASE_URL",),
    "tools.register_container_audit_worker_pc": ("DEFAULT_ENDPOINT_URL",),
    "Container_Audit": ("UPDATE_BOOTSTRAP_MANIFEST_URL",),
}


@pytest.fixture(autouse=True)
def pin_test_server_addresses(monkeypatch):
    """Pin loaded and later-imported defaults without importing unused products."""
    patched = set()
    origin = urlsplit(_TEST_SERVER_ORIGIN)

    def pin_loaded_modules():
        for name, attributes in _TEST_SERVER_DEFAULTS.items():
            module = sys.modules.get(name)
            identity = (name, id(module))
            if module is None or identity in patched or not all(hasattr(module, attribute) for attribute in attributes):
                continue
            if not all(isinstance(getattr(module, attribute), str) for attribute in attributes):
                continue
            # MonkeyPatch.setattr imports inspect; mark first so our import hook
            # cannot re-enter the same module while applying its override.
            patched.add(identity)
            for attribute in attributes:
                original = getattr(module, attribute)
                parsed = urlsplit(original)
                replacement = urlunsplit((origin.scheme, origin.netloc, parsed.path, parsed.query, parsed.fragment))
                monkeypatch.setattr(module, attribute, replacement)
                # The direct onboarding API captured this default at definition
                # time; changing the module constant alone leaves it on production.
                if name == "current_user_onboarding":
                    onboard = getattr(module, "onboard_current_user", None)
                    while onboard is not None:
                        defaults = getattr(onboard, "__kwdefaults__", None)
                        if defaults and defaults.get("server_base_url") == original:
                            monkeypatch.setattr(onboard, "__kwdefaults__", {**defaults, "server_base_url": replacement})
                        onboard = getattr(onboard, "__wrapped__", None)

    original_import = builtins.__import__
    original_import_module = importlib.import_module

    def import_and_pin(*args, **kwargs):
        module = original_import(*args, **kwargs)
        pin_loaded_modules()
        return module

    def import_module_and_pin(*args, **kwargs):
        module = original_import_module(*args, **kwargs)
        pin_loaded_modules()
        return module

    monkeypatch.setattr(builtins, "__import__", import_and_pin)
    monkeypatch.setattr(importlib, "import_module", import_module_and_pin)
    pin_loaded_modules()


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
    if os.name == "nt":
        import winreg

        open_key = winreg.OpenKey
        def isolated_key(hive, name, *args, **kwargs):
            if hive == winreg.HKEY_CURRENT_USER and name == r"Software\Microsoft\Windows\CurrentVersion\Run":
                raise FileNotFoundError("test has no ambient relay registration")
            return open_key(hive, name, *args, **kwargs)
        # Ambient HKCU autostart belongs to the operator, never a test dataset.
        patch.setattr(winreg, "OpenKey", isolated_key)
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
    prodblock = os.environ.get("KMTECH_TEST_PRODBLOCK")
    child_paths = [prodblock] if prodblock else []
    inherited_path = os.environ.get("PYTHONPATH")
    if inherited_path:
        child_paths.append(inherited_path)
    child_paths.extend((str(test_dir), str(test_dir.parent)))
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(child_paths))
    import logistics_runtime_profile as runtime_profile

    machine_value = runtime_profile._machine_environment_value

    @functools.wraps(machine_value)
    def machine_value_without_host_transition(name):
        # The host's administrator switch never reaches a test; a test that
        # needs it injects a fake registry behind the unwrapped reader.
        if name == runtime_profile.LEGACY_LABEL_TRANSITION_ENV:
            return ""
        return machine_value(name)

    monkeypatch.setattr(
        runtime_profile, "_machine_environment_value", machine_value_without_host_transition
    )


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


def _tracked_ca_mutex_acquire(guard, acquire):
    """CA's release() lease adapter; also used by isolated client children."""
    from types import SimpleNamespace

    def closable_acquire(*args, **kwargs):
        raw = acquire(*args, **kwargs)
        if raw is None:
            return None
        return SimpleNamespace(abandoned=raw.abandoned, close=raw.release)

    tracked_acquire = guard.wrap_mutex_acquire(closable_acquire)

    def ca_acquire(*args, **kwargs):
        lease = tracked_acquire(*args, **kwargs)
        if lease is not None:
            lease.release = lease.close
        return lease

    return ca_acquire


@pytest.fixture(autouse=True)
def ca_remote_lock_guard(monkeypatch, isolate_product_state):
    """Track the real CA admission lease without changing fence decisions."""
    from tests.lock_remote_guard import LockRemoteGuard
    import writer_session_fence as fence

    guard = LockRemoteGuard()
    monkeypatch.setattr(fence, "_acquire_named_mutex", _tracked_ca_mutex_acquire(guard, fence._acquire_named_mutex))
    _instrument_ca_thread_and_sqlite_locks(guard, monkeypatch)
    guard.instrument_transports(monkeypatch)
    yield guard
    guard.assert_clean()


def _instrument_ca_thread_and_sqlite_locks(guard, monkeypatch):
    """Observe real locks/transactions, including objects created during imports."""
    import gc
    import sqlite3

    raw_factories = {name: getattr(threading, name) for name in ("Lock", "RLock")}
    raw_types = tuple(type(factory()) for factory in raw_factories.values())
    raw_connect = sqlite3.connect
    wrapped = {}

    class Cursor:
        def __init__(self, raw, connection):
            self.raw, self.connection = raw, connection

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def __iter__(self):
            return iter(self.raw)

        def execute(self, *args, **kwargs):
            try:
                self.raw.execute(*args, **kwargs)
                return self
            finally:
                self.connection.update_tracking()

        def executemany(self, *args, **kwargs):
            try:
                self.raw.executemany(*args, **kwargs)
                return self
            finally:
                self.connection.update_tracking()

        def executescript(self, *args, **kwargs):
            try:
                self.raw.executescript(*args, **kwargs)
                return self
            finally:
                self.connection.update_tracking()

    class Connection:
        def __init__(self, raw):
            object.__setattr__(self, "raw", raw)
            object.__setattr__(self, "tracked", False)
            self.update_tracking()

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def __setattr__(self, name, value):
            if name in {"raw", "tracked"}:
                object.__setattr__(self, name, value)
            else:
                setattr(self.raw, name, value)

        def update_tracking(self):
            if self.raw.in_transaction and not self.tracked:
                guard.enter(id(self), "sqlite transaction")
                self.tracked = True
            elif not self.raw.in_transaction and self.tracked:
                guard.leave(id(self))
                self.tracked = False

        def cursor(self, *args, **kwargs):
            return Cursor(self.raw.cursor(*args, **kwargs), self)

        def execute(self, *args, **kwargs):
            return self.cursor().execute(*args, **kwargs)

        def executemany(self, *args, **kwargs):
            return self.cursor().executemany(*args, **kwargs)

        def executescript(self, *args, **kwargs):
            return self.cursor().executescript(*args, **kwargs)

        def commit(self):
            try:
                return self.raw.commit()
            finally:
                self.update_tracking()

        def rollback(self):
            try:
                return self.raw.rollback()
            finally:
                self.update_tracking()

        def backup(self, target, *args, **kwargs):
            raw_target = target.raw if isinstance(target, Connection) else target
            try:
                return self.raw.backup(raw_target, *args, **kwargs)
            finally:
                self.update_tracking()
                if isinstance(target, Connection):
                    target.update_tracking()

        def close(self):
            try:
                return self.raw.close()
            finally:
                guard.leave(id(self))
                self.tracked = False

        def __enter__(self):
            self.raw.__enter__()
            self.update_tracking()
            return self

        def __exit__(self, *args):
            try:
                return self.raw.__exit__(*args)
            finally:
                self.update_tracking()

    def wrap(value):
        if isinstance(value, raw_types):
            if id(value) not in wrapped:
                wrapped[id(value)] = guard.wrap_lock(value)
            return wrapped[id(value)]
        if isinstance(value, sqlite3.Connection):
            try:
                value.in_transaction
            except sqlite3.ProgrammingError:
                return value  # Closed import/fixture artifacts cannot hold a transaction.
            if id(value) not in wrapped:
                wrapped[id(value)] = Connection(value)
            return wrapped[id(value)]
        return value

    def connect(*args, **kwargs):
        return wrap(raw_connect(*args, **kwargs))

    factories = {}
    for name, raw_factory in raw_factories.items():
        def factory(*args, _raw=raw_factory, **kwargs):
            return wrap(_raw(*args, **kwargs))
        factories[name] = factory
        monkeypatch.setattr(threading, name, factory)
    monkeypatch.setattr(sqlite3, "connect", connect)

    root = Path(__file__).resolve().parents[1]
    owners = []
    modules = set()
    for module in list(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if filename and Path(filename).resolve().is_relative_to(root):
            modules.add(module.__name__)
            owners.append(module)
            owners.extend(value for value in vars(module).values()
                          if isinstance(value, type) and value.__module__ == module.__name__)
    for value in gc.get_objects():
        if type(value).__module__ in modules and hasattr(value, "__dict__"):
            owners.append(value)
    for owner in owners:
        for name, value in list(vars(owner).items()):
            replacement = wrap(value)
            for factory_name, raw_factory in raw_factories.items():
                if value is raw_factory:
                    replacement = factories[factory_name]
            if value is raw_connect:
                replacement = connect
            if replacement is not value:
                monkeypatch.setattr(owner, name, replacement)

    # The application supports injected HTTP clients. Register those boundaries
    # too, so a fake response cannot hide a product lock/HTTP overlap.
    import requests.sessions
    from container_admin_pin import AdminPinClient
    from transfer_client import LogisticsTransferClient

    def register_injected_transport(instance):
        transport = getattr(instance, "transport", None)
        if callable(transport):
            monkeypatch.setattr(instance, "transport", guard.wrap_transport(transport, "PIN HTTP"))
        session = getattr(instance, "session", None)
        if session is not None and not isinstance(session, requests.sessions.Session):
            request = getattr(session, "request", None)
            if callable(request):
                monkeypatch.setattr(session, "request", guard.wrap_transport(request, "injected HTTP"))

    for cls in (AdminPinClient, LogisticsTransferClient):
        original = cls.__init__
        def initialize(instance, *args, _init=original, **kwargs):
            _init(instance, *args, **kwargs)
            register_injected_transport(instance)
        monkeypatch.setattr(cls, "__init__", initialize)
    for owner in owners:
        if isinstance(owner, (AdminPinClient, LogisticsTransferClient)):
            register_injected_transport(owner)


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


@pytest.fixture
def ca_late_result_adapter_factory(tmp_path, ca_remote_lock_guard):
    from test_late_result_adapter import RelayLateAdapter
    adapters = []
    def factory(transport):
        adapter = RelayLateAdapter(tmp_path / str(len(adapters)), transport, ca_remote_lock_guard)
        adapters.append(adapter)
        return adapter
    yield factory
    for adapter in adapters:
        adapter.close()

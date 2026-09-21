"""Propagate pytest writer-admission isolation into child interpreters.

Container_Audit writer_sink always admits against canonical_control_root().
That helper treats "whatever LOCALAPPDATA currently expands to" as production
and therefore returns the machine-global mutex name. Child processes spawned
by session-sync / user-relay tests must never take
Local\\KMTech.ContainerAudit.WriterAdmission.v1.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import json
from pathlib import Path
import os
import sys
from urllib.parse import parse_qs, unquote, urlsplit


_ROOT_ENV = "KMTECH_TEST_CA_WRITER_ROOT"
_MUTEX_ENV = "KMTECH_TEST_CA_WRITER_MUTEX"
_MARKER_ENV = "KMTECH_TEST_CA_SITECUSTOMIZE_MARKER"
_TARGET_MODULE = "writer_session_fence"


def _resolved_path(value) -> Path:
    path = str(Path(value).resolve())
    # pytest uses extended Windows paths during cleanup; these name the same files.
    if os.name == "nt" and path.startswith("\\\\?\\"):
        path = "\\\\" + path[8:] if path.startswith("\\\\?\\UNC\\") else path[4:]
    return Path(path)


def install_write_boundary() -> None:
    """Observe and deny Python filesystem mutations outside the runner's task root."""
    configured = os.environ.get("KMTECH_TEST_CA_TASK_ROOT")
    if not configured or getattr(sys, "_kmtech_ca_write_boundary", False):
        return
    root = _resolved_path(configured)
    null_device = _resolved_path(os.devnull)
    log = root / "boundary-violations.jsonl"
    single_path = {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.utime",
                   "os.truncate", "os.chown", "sqlite3.connect"}
    two_paths = {"os.rename", "os.link", "os.symlink"}

    def guard(event, args):
        if event == "open":
            path, mode, flags = args
            if not (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
                return
            paths = (path,)
        elif event in single_path:
            paths = args[:1]
        elif event in two_paths:
            paths = args[:2]
        else:
            return
        for path in paths:
            if isinstance(path, int) or path is None:
                continue
            value = os.fsdecode(path)
            if event == "sqlite3.connect" and value.startswith("file:"):
                uri = urlsplit(value)
                if parse_qs(uri.query).get("mode") == ["memory"]:
                    continue
                value = unquote(uri.path)
                if uri.netloc and uri.netloc != "localhost":
                    value = f"//{uri.netloc}{value}"
                elif os.name == "nt" and len(value) > 2 and value[0] == "/" and value[2] == ":":
                    value = value[1:]
            if value == ":memory:" and event == "sqlite3.connect":
                continue
            if os.path.normcase(value) == os.path.normcase(os.devnull):
                continue
            resolved = _resolved_path(value)
            if resolved == null_device or resolved.is_relative_to(root):
                continue
            with log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"event": event, "path": str(resolved), "pid": os.getpid()}) + "\n")
            raise AssertionError(f"test write outside task root: {event}: {resolved}")

    sys.addaudithook(guard)
    sys._kmtech_ca_write_boundary = True


def _write_marker() -> None:
    marker = os.environ.get(_MARKER_ENV, "").strip()
    if not marker:
        return
    path = Path(marker)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("loaded\n", encoding="utf-8")


def _install(module) -> None:
    if getattr(module, "__kmtech_test_ca_writer_isolated__", False):
        return
    isolated_root = Path(os.environ[_ROOT_ENV]).resolve()
    isolated_mutex = os.environ[_MUTEX_ENV]
    if not isolated_mutex or isolated_mutex == module.WRITER_MUTEX_NAME:
        raise AssertionError("test Container_Audit writer mutex must be isolated")

    acquire_named_mutex = module._acquire_named_mutex

    def canonical_control_root(_environ=None):
        return isolated_root

    def writer_admission_mutex_name(_control_root, *, environ=None):
        return isolated_mutex

    def guarded_acquire_named_mutex(name: str, timeout_seconds: float):
        if name == module.WRITER_MUTEX_NAME:
            raise AssertionError(
                "test child attempted to acquire the machine-global canonical "
                f"writer-admission mutex: {name}"
            )
        return acquire_named_mutex(name, timeout_seconds)

    module.canonical_control_root = canonical_control_root
    module.writer_admission_mutex_name = writer_admission_mutex_name
    module._acquire_named_mutex = guarded_acquire_named_mutex
    module.__kmtech_test_ca_writer_isolated__ = True


class _WriterFenceLoader(importlib.abc.Loader):
    def __init__(self, wrapped) -> None:
        self._wrapped = wrapped

    def create_module(self, spec):
        create_module = getattr(self._wrapped, "create_module", None)
        return None if create_module is None else create_module(spec)

    def exec_module(self, module) -> None:
        self._wrapped.exec_module(module)
        _install(module)


class _WriterFenceFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname != _TARGET_MODULE:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None or spec.loader is None:
            return spec
        spec.loader = _WriterFenceLoader(spec.loader)
        return spec


install_write_boundary()

if os.environ.get(_ROOT_ENV, "").strip() and os.environ.get(_MUTEX_ENV, "").strip():
    if os.name == "nt":
        import winreg

        _open_key = winreg.OpenKey
        def _isolated_key(hive, name, *args, **kwargs):
            if hive == winreg.HKEY_CURRENT_USER and name == r"Software\Microsoft\Windows\CurrentVersion\Run":
                raise FileNotFoundError("test child has no ambient relay registration")
            return _open_key(hive, name, *args, **kwargs)
        winreg.OpenKey = _isolated_key
    _write_marker()
    loaded = sys.modules.get(_TARGET_MODULE)
    if loaded is not None:
        _install(loaded)
    elif not any(isinstance(finder, _WriterFenceFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _WriterFenceFinder())

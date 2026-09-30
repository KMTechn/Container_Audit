from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from runtime_instance import acquire_runtime_instance, runtime_mutex_name


def test_runtime_mutex_name_is_stable_and_data_root_scoped(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"

    assert runtime_mutex_name(first_root) == runtime_mutex_name(first_root / ".")
    assert runtime_mutex_name(first_root) != runtime_mutex_name(second_root)
    assert str(first_root) not in runtime_mutex_name(first_root)
    assert runtime_mutex_name(first_root).startswith("Global\\KMTech.ContainerAudit.")


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex contract")
def test_same_pc_same_data_root_allows_only_one_runtime(tmp_path):
    first = acquire_runtime_instance(tmp_path)
    assert first is not None
    try:
        assert acquire_runtime_instance(tmp_path) is None
    finally:
        first.release()

    replacement = acquire_runtime_instance(tmp_path)
    assert replacement is not None
    replacement.release()


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex contract")
def test_same_pc_different_data_roots_do_not_collide(tmp_path):
    first = acquire_runtime_instance(tmp_path / "first")
    second = acquire_runtime_instance(tmp_path / "second")
    assert first is not None
    assert second is not None
    first.release()
    second.release()


@pytest.mark.skipif(os.name != "nt", reason="Windows mandatory integrity contract")
def test_existing_runtime_and_writer_mutexes_work_across_integrity_levels(tmp_path):
    # Only this short-lived diagnostic child lowers its own token. No relay,
    # GUI, host token, object security descriptor or runtime files are changed.
    child_code = r'''
import ctypes, json, sys
from ctypes import wintypes
sys.path.insert(0, sys.argv[1])
from runtime_instance import acquire_runtime_instance, runtime_mutex_name
from writer_session_fence import _acquire_named_mutex, _named_mutex_held_by_other

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]
class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]

k = ctypes.WinDLL("kernel32", use_last_error=True)
a = ctypes.WinDLL("advapi32", use_last_error=True)
k.GetCurrentProcess.restype = wintypes.HANDLE
k.CloseHandle.argtypes = [wintypes.HANDLE]
k.LocalFree.argtypes = [ctypes.c_void_p]
a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
a.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
a.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
a.GetLengthSid.argtypes = [ctypes.c_void_p]
a.GetLengthSid.restype = wintypes.DWORD
token = wintypes.HANDLE()
sid = ctypes.c_void_p()
assert a.OpenProcessToken(k.GetCurrentProcess(), 0x0088, ctypes.byref(token)), ctypes.get_last_error()
try:
    assert a.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(sid)), ctypes.get_last_error()
    label = TOKEN_MANDATORY_LABEL(SID_AND_ATTRIBUTES(sid, 0x20))
    assert a.SetTokenInformation(token, 25, ctypes.byref(label), ctypes.sizeof(label) + a.GetLengthSid(sid)), ctypes.get_last_error()
finally:
    if sid: k.LocalFree(sid)
    k.CloseHandle(token)

k.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
k.CreateMutexW.restype = wintypes.HANDLE
ctypes.set_last_error(0)
old_handle = k.CreateMutexW(None, False, runtime_mutex_name(sys.argv[2]))
old_error = ctypes.get_last_error()
if old_handle: k.CloseHandle(old_handle)
try:
    lease = acquire_runtime_instance(sys.argv[2])
    result = {"existing": lease is None, "error": None}
    if lease is not None: lease.release()
except OSError as exc:
    result = {"existing": False, "error": exc.errno}
writer_busy = _acquire_named_mutex(sys.argv[3], 0)
assert writer_busy is None
assert _named_mutex_held_by_other(sys.argv[3]) is True
writer_free = _acquire_named_mutex(sys.argv[3] + ".available", 0)
assert writer_free is not None and writer_free.abandoned is False
writer_free.release()
print(json.dumps({"old_opened": bool(old_handle), "old_error": old_error, "product": result}))
'''
    from writer_session_fence import _acquire_named_mutex

    first = acquire_runtime_instance(tmp_path)
    assert first is not None
    writer_name = runtime_mutex_name(tmp_path) + ".writer"
    writer = _acquire_named_mutex(writer_name, 0)
    assert writer is not None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexExW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                      ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateMutexExW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    keeper = kernel32.CreateMutexExW(None, writer_name + ".available", 0, 0x00100001)
    assert keeper, ctypes.get_last_error()
    try:
        child = subprocess.run(
            [sys.executable, "-I", "-B", "-c", child_code,
             str(Path(__file__).resolve().parents[1]), str(tmp_path), writer_name],
            cwd=tmp_path, capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        assert child.returncode == 0, child.stderr
        result = json.loads(child.stdout)
        assert result["old_opened"] is False and result["old_error"] == 5
        assert result["product"] == {"existing": True, "error": None}
        assert acquire_runtime_instance(tmp_path) is None
        available = _acquire_named_mutex(writer_name + ".available", 0)
        assert available is not None and available.abandoned is False
        available.release()
    finally:
        first.release()
        writer.release()
        kernel32.CloseHandle(keeper)
    replacement = acquire_runtime_instance(tmp_path)
    assert replacement is not None
    replacement.release()


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex security")
def test_runtime_does_not_treat_denied_access_as_an_existing_lease(tmp_path):
    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", ctypes.c_ulong),
                    ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", ctypes.c_int)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong,
                        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    # An empty protected DACL denies SYNCHRONIZE. Tighten only this unique test
    # object's permissions; the production function must propagate error 5.
    assert convert("D:P", 1, ctypes.byref(descriptor), None)
    attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
    kernel32.CreateMutexExW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                      ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateMutexExW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    handle = None
    try:
        handle = kernel32.CreateMutexExW(ctypes.byref(attributes), runtime_mutex_name(tmp_path), 0, 0)
        assert handle, ctypes.get_last_error()
        with pytest.raises(OSError) as caught:
            acquire_runtime_instance(tmp_path)
        assert caught.value.errno == 5
    finally:
        if handle:
            kernel32.CloseHandle(handle)
        kernel32.LocalFree(descriptor)

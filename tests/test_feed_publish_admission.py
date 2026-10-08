from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

import auto_update as update
import writer_session_fence as fence
from tests.test_writer_session_fence import _active_payload, _write_active


NAMES = ("manifest.json", "manifest.sig", "packet.zip")


@pytest.mark.parametrize("mutation", ["new-caller", "import-alias", "source"])
def test_copy_helper_inventory_rejects_unapproved_callers_and_sources(tmp_path, mutation):
    from tests.test_container_writer_sink_inventory import _load_module, _write_minimal_inventory_fixture

    derive = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "import auto_update\ndef main():\n    pass\n")
    root = Path(__file__).resolve().parents[1]
    target = tmp_path / "auto_update.py"
    source = (root / "auto_update.py").read_text(encoding="utf-8")
    target.write_text(source, encoding="utf-8")
    helper = "auto_update._copy_prepared_bytes"
    before = derive.derive_inventory(tmp_path)
    row = next(row for row in before["closure_direct_mutation_functions"] if row["node"] == helper)
    assert row["coverage_status"] == "covered"
    assert row["direct_callers"] == ["auto_update.copy_prepared_file", "auto_update.stage_prepared_copies"]
    assert row["caller_guard_sources"] == ["auto_update_control"]
    assert not any(row["target"] == helper for row in before["caller_fence_reference_failures"])
    if mutation == "source":
        marker = '@writer_sink("auto_update_control", probe_only=True)\ndef stage_prepared_copies'
        assert source.count(marker) == 1
        target.write_text(source.replace(marker, '@writer_sink("gui_tray_state_save", probe_only=True)\ndef stage_prepared_copies'), encoding="utf-8")
    elif mutation == "new-caller":
        target.write_text(source + "\ndef bypass(source, target):\n    _copy_prepared_bytes(source, target)\n", encoding="utf-8")
    else:
        (tmp_path / "Container_Audit.py").write_text(
            "from auto_update import _copy_prepared_bytes as copy_alias\ndef main():\n    copy_alias(None, None)\n",
            encoding="utf-8")
    rejected = derive.derive_inventory(tmp_path)
    assert helper in {row["node"] for row in rejected["uncovered_direct_mutation_functions"]}
    if mutation == "new-caller":
        assert helper in {row["target"] for row in rejected["caller_fence_reference_failures"]}


def _publish(attempt, stage):
    # Keep the same regression runnable against the pre-K11 public signature.
    if hasattr(update, "stage_prepared_copies"):
        update.publish_download(stage, update.stage_prepared_copies(attempt, stage))
    else:
        update.publish_download(attempt, stage)


def _inputs(root, packet_mib=1):
    stage = root / "stage"
    stage.mkdir()
    attempt = stage / ("download-" + "a" * 32)
    attempt.mkdir()
    (attempt / "manifest.json").write_bytes(b'{"version":"fixture"}')
    (attempt / "manifest.sig").write_bytes(b"fixture signature")
    with (attempt / "packet.zip").open("wb") as stream:
        block = bytes(range(256)) * 4096
        for _ in range(packet_mib):
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())
    for name in (*NAMES, "prepared.json"):
        (stage / name).write_bytes(("old " + name).encode())
    return attempt, stage


def _fixed_bytes(stage):
    return {name: (stage / name).read_bytes() for name in (*NAMES, "prepared.json")}


def test_large_publish_releases_real_admission_between_reads(tmp_path, monkeypatch):
    attempt, stage = _inputs(tmp_path, packet_mib=64)
    original_acquire = fence._acquire_named_mutex
    original_source = update.unredirected_source
    publisher = threading.get_ident()
    holds, waits, errors = [], [], []
    ready, stop = threading.Event(), threading.Event()

    class ObservedLease:
        def __init__(self, lease):
            self.lease = lease
            self.started = time.monotonic()

        def __getattr__(self, name):
            return getattr(self.lease, name)

        def release(self):
            if threading.get_ident() == publisher:
                holds.append(time.monotonic() - self.started)
            self.lease.release()

    def acquire(name, timeout_seconds):
        lease = original_acquire(name, timeout_seconds)
        return ObservedLease(lease) if lease is not None else None

    class SlowRead:
        def __init__(self, incoming):
            self.incoming = incoming

        def __getattr__(self, name):
            return getattr(self.incoming, name)

        def read(self, size=-1):
            # Deterministic HDD read latency; real writes/fsync/mutex stay intact.
            time.sleep(0.002)
            return self.incoming.read(size)

    @contextmanager
    def source(path, **kwargs):
        with original_source(path, **kwargs) as incoming:
            yield SlowRead(incoming) if path.name == "packet.zip" else incoming

    def scans():
        while not stop.is_set():
            started = time.monotonic()
            try:
                with fence.writer_admission("gui_tray_state_save"):
                    waits.append(time.monotonic() - started)
            except fence.WriterFenceError as exc:
                errors.append(exc.code)
            finally:
                ready.set()
            stop.wait(0.1)

    monkeypatch.setattr(fence, "_acquire_named_mutex", acquire)
    monkeypatch.setattr(update, "unredirected_source", source)
    worker = threading.Thread(target=scans, name="feed-publish-scan")
    worker.start()
    started = time.monotonic()
    try:
        assert ready.wait(5)
        _publish(attempt, stage)
    finally:
        stop.set()
        worker.join(10)
    assert not worker.is_alive()
    metrics = {"packet_bytes": (attempt / "packet.zip").stat().st_size,
               "read_delay_seconds": 0.002, "admissions": len(holds),
               "hold_max_seconds": max(holds, default=0),
               "hold_sum_seconds": sum(holds), "publish_seconds": time.monotonic() - started,
               "scan_wait_max_seconds": max(waits, default=0),
               "scan_admissions": len(waits), "scan_denials": errors}
    (tmp_path / "admission-metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    assert not errors
    assert len(waits) >= 2
    assert holds and max(holds) <= 0.2, metrics
    for name in NAMES:
        with (attempt / name).open("rb") as incoming, (stage / name).open("rb") as published:
            assert hashlib.file_digest(incoming, "sha256").digest() == \
                hashlib.file_digest(published, "sha256").digest()
    assert (stage / "prepared.json").read_bytes() == b"old prepared.json"


@pytest.mark.parametrize("failure", ["read", "disk", "fence", "hardlink", "oversized"])
def test_copy_failure_preserves_all_fixed_files(tmp_path, monkeypatch, failure):
    attempt, stage = _inputs(tmp_path)
    before = _fixed_bytes(stage)
    original_source = update.unredirected_source
    original_fsync = update.os.fsync
    control = fence.canonical_control_root()
    if failure == "hardlink":
        os.link(attempt / "packet.zip", attempt / "packet-alias")
    elif failure == "oversized":
        with (attempt / "manifest.sig").open("ab") as stream:
            stream.truncate(1024 * 1024 + 1)

    class InterruptedRead:
        def __init__(self, incoming):
            self.incoming = incoming
            self.reads = 0

        def __getattr__(self, name):
            return getattr(self.incoming, name)

        def read(self, size=-1):
            self.reads += 1
            if self.reads == 2:
                raise OSError("injected prepared read failure")
            return self.incoming.read(size)

    @contextmanager
    def source(path, **kwargs):
        with original_source(path, **kwargs) as incoming:
            if path.name == "packet.zip" and failure == "fence":
                _write_active(control, _active_payload())
            yield InterruptedRead(incoming) if path.name == "packet.zip" and failure == "read" else incoming

    def fsync(fd):
        if failure == "disk" and os.fstat(fd).st_size > 256 * 1024:
            raise OSError("injected prepared disk failure")
        return original_fsync(fd)

    monkeypatch.setattr(update, "unredirected_source", source)
    monkeypatch.setattr(update.os, "fsync", fsync)
    with pytest.raises((OSError, ValueError, fence.WriterFenceError)):
        _publish(attempt, stage)
    assert _fixed_bytes(stage) == before


def test_relay_cycle_and_loop_call_real_feed_without_admission(tmp_path, monkeypatch):
    import data_generation_guard
    import user_relay

    original_feed = update.prepare_feed_packet
    observed = []

    def feed(root):
        observed.append(int(getattr(fence._WRITER_LOCAL, "depth", 0)))
        assert observed[-1] == 0
        return original_feed(root)

    monkeypatch.setattr(update, "control_root", lambda _root: None)
    monkeypatch.setattr(update, "prepare_feed_packet", feed)
    monkeypatch.setattr(data_generation_guard, "probe_before_owner_paths", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(user_relay, "run_session_direct_sync_once", lambda **_kwargs: {"status": "PASS", "returncode": 0})
    monkeypatch.setattr(user_relay, "_read_json", lambda _path: {"status": "idle"})
    result = user_relay.run_persistent_relay_loop(
        lambda: user_relay._runtime_cycle(app_root=tmp_path / "app", direct_sync_root=tmp_path / "sync",
                                        scan_source_dir=tmp_path / "events", data_root=tmp_path / "data"),
        status_path=tmp_path / "relay-status.json", max_cycles=1)
    assert observed == [0]
    assert result["last_cycle"]["status"] == "idle"


@contextmanager
def _scan_process(root):
    ready, stop, result = (root / name for name in ("scan-ready", "scan-stop", "scan-result.json"))
    code = '''import json, pathlib, sys, time
import writer_session_fence as fence
ready, stop, result = map(pathlib.Path, sys.argv[1:])
waits, denials = [], []
admissions = 0
while not stop.exists():
    started = time.perf_counter()
    try:
        with fence.writer_admission("gui_tray_state_save"):
            waits.append(time.perf_counter() - started)
            admissions += 1
    except fence.WriterFenceError as exc:
        waits.append(time.perf_counter() - started)
        denials.append(exc.code)
    ready.touch()
    time.sleep(0.1)
result.write_text(json.dumps(dict(admissions=admissions, wait_max_ms=max(waits, default=0)*1000, denials=denials)))
'''
    child = subprocess.Popen([sys.executable, "-B", "-c", code, str(ready), str(stop), str(result)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    measurements = {}
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists(), "scan child did not reach real writer admission"
        yield measurements
    finally:
        stop.touch()
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, (child.returncode, len(stdout), len(stderr))
        measurements.update(json.loads(result.read_text()))


def _observe_admissions(monkeypatch, phase):
    acquire = fence._acquire_named_mutex
    publisher = threading.get_ident()
    records = []

    class Lease:
        def __init__(self, raw):
            self.raw = raw
            self.started = time.perf_counter()
            self.phase = phase[0]

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def release(self):
            if threading.get_ident() == publisher:
                records.append({"phase": self.phase, "hold_ms": (time.perf_counter() - self.started) * 1000})
            self.raw.release()

    def observed(name, timeout_seconds):
        raw = acquire(name, timeout_seconds)
        return Lease(raw) if raw is not None else None

    monkeypatch.setattr(fence, "_acquire_named_mutex", observed)
    return records


def test_download_copy_publish_and_marker_with_other_process(tmp_path, monkeypatch):
    attempt, stage = _inputs(tmp_path, packet_mib=64)
    phase = ["download-create"]
    records = _observe_admissions(monkeypatch, phase)
    with _scan_process(tmp_path) as scans:
        (attempt / "packet.zip").unlink()
        update.write_download_bytes(attempt / "packet.zip", b"")
        phase[0] = "download-chunk"
        block = bytes(range(256)) * 1024
        for _ in range(256):
            update.write_download_chunk(attempt / "packet.zip", block)
        phase[0] = "copy"
        copies = update.stage_prepared_copies(attempt, stage)
        phase[0] = "publish"
        update.publish_download(stage, copies)
        for name in NAMES:
            with (attempt / name).open("rb") as incoming, (stage / name).open("rb") as outgoing:
                assert hashlib.file_digest(incoming, "sha256").digest() == hashlib.file_digest(outgoing, "sha256").digest()
        phase[0] = "prepared.json"
        update.write_json_durable(stage / "prepared.json", {"status": "PREPARED"})
    summary = {name: {"count": len(values), "max_ms": max(values), "sum_ms": sum(values)}
               for name in {row["phase"] for row in records}
               if (values := [row["hold_ms"] for row in records if row["phase"] == name])}
    (tmp_path / "phase-metrics.json").write_text(json.dumps({"phases": summary, "scans": scans}), encoding="utf-8")
    assert not scans["denials"]
    assert scans["admissions"] >= 2
    assert summary["copy"]["count"] == 1
    assert summary["publish"]["max_ms"] < 100
    assert max(row["hold_ms"] for row in records if row["phase"] != "prepared.json") <= 200


@pytest.mark.parametrize("name", ["write_download_bytes", "write_download_chunk", "stage_prepared_copies", "_run_download_attempt"])
def test_staging_probe_refuses_an_inherited_admission(tmp_path, name):
    attempt, stage = _inputs(tmp_path)
    before = _fixed_bytes(stage)
    with fence.writer_admission("gui_tray_state_save"):
        with pytest.raises(fence.WriterFencedError) as caught:
            if name == "stage_prepared_copies":
                update.stage_prepared_copies(attempt, stage)
            elif name == "_run_download_attempt":
                update._run_download_attempt(stage, lambda *_args: pytest.fail("nested staging body ran"))
            else:
                getattr(update, name)(attempt / "nested.bin", b"nested write")
    assert caught.value.code == "STAGING_WRITER_ADMISSION_HELD"
    assert not (attempt / "nested.bin").exists()
    assert _fixed_bytes(stage) == before


def test_fence_actors_only_declare_the_staging_path():
    root = Path(__file__).resolve().parents[1]
    for name in ("INSTALL_CANONICAL_PORTABLE.ps1", "INSTALL_THIS_PC.ps1", "tools/bootstrap_integrity.ps1", "current_user_onboarding.py"):
        text = (root / name).read_text(encoding="utf-8-sig")
        references = [line.strip() for line in text.splitlines() if "staging_root" in line]
        if name == "INSTALL_THIS_PC.ps1":
            assert references == ["staging_root=(Join-Path $OperatorLocalAppDataRoot 'KMTech\\ContainerAudit\\updates')"]
        else:
            assert references == []


def test_system_copy_keeps_real_admission_and_original_body(tmp_path, monkeypatch):
    import ast

    root = Path(__file__).resolve().parents[1]
    original = subprocess.check_output(["git", "-C", str(root), "show", "9af8a15:auto_update.py"],
                                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).decode("utf-8")
    old = next(node for node in ast.parse(original).body if isinstance(node, ast.FunctionDef) and node.name == "copy_prepared_file")
    current_text = (root / "auto_update.py").read_text(encoding="utf-8")
    current_tree = ast.parse(current_text)
    current = next(node for node in current_tree.body
                   if isinstance(node, ast.FunctionDef) and node.name == "_copy_prepared_bytes")
    wrapper = next(node for node in current_tree.body
                   if isinstance(node, ast.FunctionDef) and node.name == "copy_prepared_file")
    assert ast.dump(old.args) == ast.dump(wrapper.args)
    assert [ast.dump(node) for node in old.decorator_list] == [ast.dump(node) for node in wrapper.decorator_list]
    assert original.splitlines()[old.body[0].lineno - 1:old.end_lineno] == \
        current_text.splitlines()[current.body[0].lineno - 1:current.end_lineno]
    assert [ast.dump(node, include_attributes=False) for node in old.body] == \
        [ast.dump(node, include_attributes=False) for node in current.body]
    helper = update._copy_prepared_bytes
    depths = []

    def observed(*args, **kwargs):
        depths.append(int(getattr(fence._WRITER_LOCAL, "depth", 0)))
        return helper(*args, **kwargs)

    monkeypatch.setattr(update, "_copy_prepared_bytes", observed)
    source, target = tmp_path / "manifest.json", tmp_path / "protected.json"
    source.write_bytes(b"SYSTEM fixture")
    update.copy_prepared_file(source, target)
    assert depths == [1]
    assert target.read_bytes() == source.read_bytes()


def test_cleanup_rejects_redirected_attempt_without_deleting_foreign_data(tmp_path):
    stage, foreign = tmp_path / "stage", tmp_path / "foreign"
    foreign.mkdir()
    preserved = foreign / "manifest.json"
    preserved.write_bytes(b"foreign source")

    def operation(attempt, _copies):
        attempt.rmdir()
        command = ("$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path '"
                   + str(attempt).replace("'", "''") + "' -Target '"
                   + str(foreign).replace("'", "''") + "' | Out-Null")
        completed = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                                    "-Command", command], capture_output=True,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert completed.returncode == 0

    with pytest.raises(fence.WriterFenceError) as caught:
        update._run_download_attempt(stage, operation)
    assert caught.value.code == "FENCE_REPARSE_REJECTED"
    assert preserved.read_bytes() == b"foreign source"
    assert next(stage.glob("download-*")).is_dir()


@pytest.mark.parametrize("failure", ["read", "fence"])
def test_failed_copy_or_fenced_publish_cleans_owned_temporaries(tmp_path, monkeypatch, failure):
    stage = tmp_path / "stage"
    stage.mkdir()
    for name in (*NAMES, "prepared.json"):
        (stage / name).write_bytes(("old " + name).encode())
    before = _fixed_bytes(stage)
    original_source = update.unredirected_source

    class InterruptedRead:
        def __init__(self, incoming):
            self.incoming, self.reads = incoming, 0

        def __getattr__(self, name):
            return getattr(self.incoming, name)

        def read(self, size=-1):
            self.reads += 1
            if self.reads == 2:
                raise OSError("injected staging read failure")
            return self.incoming.read(size)

    @contextmanager
    def source(path, **kwargs):
        with original_source(path, **kwargs) as incoming:
            if path.name == "packet.zip" and failure == "fence":
                _write_active(fence.canonical_control_root(), _active_payload())
            yield InterruptedRead(incoming) if path.name == "packet.zip" and failure == "read" else incoming

    def operation(attempt, copies):
        for name in NAMES:
            update.write_download_bytes(attempt / name, b"packet" * 200000 if name == "packet.zip" else b"metadata")
        copies.update(update.stage_prepared_copies(attempt, stage))
        update.publish_download(stage, copies)

    monkeypatch.setattr(update, "unredirected_source", source)
    with pytest.raises((OSError, fence.WriterFenceError)):
        update._run_download_attempt(stage, operation)
    assert _fixed_bytes(stage) == before
    assert not list(stage.glob("download-*"))
    assert not list(stage.glob("*.tmp"))


def test_attempt_creation_error_preserves_original_failure_and_cleans_directory(tmp_path, monkeypatch):
    create = update.create_protected_stage
    original = OSError("injected post-creation failure")

    def failed(path):
        create(path)
        raise original

    monkeypatch.setattr(update, "create_protected_stage", failed)
    stage = tmp_path / "stage"
    with pytest.raises(OSError) as caught:
        update._run_download_attempt(stage, lambda *_args: pytest.fail("creation failed before download"))
    assert caught.value is original
    assert not list(stage.glob("download-*"))


def test_system_defers_for_live_relay_without_reading_fixed_packet(tmp_path, monkeypatch):
    control, stage = tmp_path / "control", tmp_path / "stage"
    control.mkdir()
    stage.mkdir()
    real_read = update.read_json
    policy = {"operator_local_app_data": os.environ["LOCALAPPDATA"], "operator_sid": "S-1-5-21-test",
              "staging_root": str(stage)}
    update.write_json_durable(control / "policy.json", policy)
    reads = []

    def read(path, *args, **kwargs):
        assert path.parent != stage, "SYSTEM read staging while the relay was live"
        reads.append(path)
        return real_read(path, *args, **kwargs)

    @contextmanager
    def lock(*_args):
        yield

    monkeypatch.setattr(update, "read_json", read)
    monkeypatch.setattr(update, "fixed_helper", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(update, "update_lock", lock)
    monkeypatch.setattr(update, "prepared_pending", lambda *_args: True)
    monkeypatch.setattr(update, "process_snapshot", lambda _root: [{"pid": os.getpid() + 1, "observable": True,
                                                                 "bootstrap": False, "role": "relay"}])
    assert update._apply_prepared(control) == 0
    assert real_read(control / "transition.json")["phase"] == "DEFERRED"
    assert all(path.parent != stage for path in reads)


@pytest.mark.parametrize("variant", ["canonical", "runtime-hash", "outside-prefix"])
def test_feed_attempts_clean_success_and_repeated_validation_failure(tmp_path, monkeypatch, variant):
    from tests.test_feed_packet_prefix import _stock_feed
    fixture = _stock_feed(tmp_path, monkeypatch, variant, real_staging=True)
    stage = fixture["stage"]
    stage.mkdir()
    for name in (*NAMES, "prepared.json"):
        (stage / name).write_bytes(b"{}" if name == "prepared.json" else ("old " + name).encode())
    before = _fixed_bytes(stage)
    foreign = stage / ("download-" + "b" * 32)
    foreign.mkdir()
    (foreign / "keep.bin").write_bytes(b"foreign attempt")
    other_temp = stage / ("packet.zip." + "c" * 32 + ".tmp")
    other_temp.write_bytes(b"foreign temporary")
    for _ in range(3):
        if variant == "canonical":
            assert update.prepare_feed_packet(tmp_path)["status"] == "PREPARED"
        else:
            with pytest.raises(ValueError):
                update.prepare_feed_packet(tmp_path)
            assert _fixed_bytes(stage) == before
        assert list(stage.glob("download-*")) == [foreign]
        assert list(stage.glob("*.tmp")) == [other_temp]
    assert (foreign / "keep.bin").read_bytes() == b"foreign attempt"
    assert other_temp.read_bytes() == b"foreign temporary"


@pytest.mark.parametrize("failure", ["stall", "rst", "fence"])
def test_mid_download_socket_failure_or_stop_cleans_attempt(tmp_path, monkeypatch, failure):
    import requests
    from tests.test_feed_packet_prefix import _stock_feed
    _stock_feed(tmp_path, monkeypatch, "canonical", real_staging=True)
    stage = tmp_path / "stage"
    stage.mkdir()
    for name in (*NAMES, "prepared.json"):
        (stage / name).write_bytes(b"{}" if name == "prepared.json" else ("old " + name).encode())
    before = _fixed_bytes(stage)
    session_get = requests.Session.get
    calls = []

    def socket_call(method):
        def observed(*args, **kwargs):
            depth = int(getattr(fence._WRITER_LOCAL, "depth", 0))
            calls.append(depth)
            assert depth == 0, "socket operation retained writer admission"
            return method(*args, **kwargs)
        return observed

    monkeypatch.setattr(socket, "create_connection", socket_call(socket.create_connection))
    monkeypatch.setattr(socket.socket, "connect", socket_call(socket.socket.connect))
    monkeypatch.setattr(socket.socket, "recv_into", socket_call(socket.socket.recv_into))

    class SocketResponse:
        def __init__(self, response):
            self.url, self.status_code = response.url, response.status_code
            self.reader, self.sender = socket.socketpair()
            self.reader.settimeout(8)
            self.stop = threading.Event()

            def send():
                try:
                    self.sender.sendall(response.body[:8192])
                    if failure == "rst":
                        self.sender.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                               struct.pack("hh" if os.name == "nt" else "ii", 1, 0))
                    elif failure == "fence":
                        self.stop.wait(0.2)
                        _write_active(fence.canonical_control_root(), _active_payload())
                        self.sender.sendall(response.body[8192:])
                    else:
                        self.stop.wait(12)
                except (OSError, BrokenPipeError):
                    pass
                finally:
                    self.sender.close()

            self.worker = threading.Thread(target=send, name="k11-feed-socket")
            self.worker.start()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

        def close(self):
            self.stop.set()
            self.reader.close()
            self.worker.join(10)
            assert not self.worker.is_alive()

        def iter_content(self, size):
            buffer = bytearray(min(size, 8192))
            while count := self.reader.recv_into(buffer):
                yield bytes(buffer[:count])

    def get(session, url, **kwargs):
        assert int(getattr(fence._WRITER_LOCAL, "depth", 0)) == 0
        response = session_get(session, url, **kwargs)
        return SocketResponse(response) if url.endswith(".zip") else response

    monkeypatch.setattr(requests.Session, "get", get)
    with _scan_process(tmp_path) as scans:
        with pytest.raises((OSError, ValueError, fence.WriterFenceError)) as failure_result:
            update.prepare_feed_packet(tmp_path)
    assert calls and set(calls) == {0}
    assert _fixed_bytes(stage) == before
    assert not list(stage.glob("download-*"))
    assert not list(stage.glob("*.tmp"))
    if failure != "fence":
        assert not scans["denials"]
    if failure == "rst" and os.name == "nt":
        assert isinstance(failure_result.value, ConnectionResetError)
    (tmp_path / "network-metrics.json").write_text(json.dumps({"failure": failure, "socket_depths": sorted(set(calls)),
                                                           "socket_calls": len(calls), "scans": scans,
                                                           "exception_type": type(failure_result.value).__name__}), encoding="utf-8")


def test_fence_before_publication_preserves_fixed_files(tmp_path, monkeypatch):
    attempt, stage = _inputs(tmp_path)
    before = _fixed_bytes(stage)
    original_source = update.unredirected_source

    @contextmanager
    def source(path, **kwargs):
        with original_source(path, **kwargs) as incoming:
            yield incoming
        if path.name == "packet.zip":
            _write_active(fence.canonical_control_root(), _active_payload())

    monkeypatch.setattr(update, "unredirected_source", source)
    with pytest.raises(fence.WriterFencedError):
        _publish(attempt, stage)
    assert _fixed_bytes(stage) == before

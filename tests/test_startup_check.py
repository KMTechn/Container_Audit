"""Installed readiness and side-effect boundaries, using existing startup inputs."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
from urllib.parse import urlunsplit

import pytest

import auto_update
import current_user_onboarding as onboarding
import data_generation_guard as guard
import item_catalog_sync as catalog
import startup_check as check
import user_relay
import writer_session_fence as fence
from kmtech_shared import data_generation as generation
from tests.test_current_user_onboarding import _ready_state, existing_possession_key_contract
from tests.test_writer_session_fence import _active_payload, _write_active

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")


def _inventory(packet):
    files = []
    for path in sorted(packet.rglob("*")):
        if path.is_file() and path.name != "bootstrap-integrity.json":
            payload = path.read_bytes()
            files.append(dict(path=path.relative_to(packet).as_posix(), size=len(payload),
                              sha256=hashlib.sha256(payload).hexdigest()))
    aggregate = hashlib.sha256("".join(
        f"{item['sha256']} {item['size']} {item['path']}\n" for item in files
    ).encode()).hexdigest()
    _write_json(packet / "bootstrap-integrity.json", dict(
        schema_version=onboarding.BOOTSTRAP_INTEGRITY_VERSION, status="PASS",
        code_root=".", file_count=len(files), aggregate_sha256=aggregate, files=files,
    ))


@pytest.fixture
def installed(tmp_path, monkeypatch, existing_possession_key_contract):
    app = tmp_path / "current/app"
    app.mkdir(parents=True)
    build = hashlib.sha1(str(tmp_path).encode()).hexdigest()
    version = "v2.0.102"
    (app / "Container_Audit.py").write_text(f"CURRENT_VERSION = {version!r}\n", encoding="utf-8")
    (app / "startup_check.py").write_bytes((ROOT / "startup_check.py").read_bytes())
    (app / "main.py").write_text("", encoding="utf-8")
    _write_json(app.parent / "portable-manifest.json", dict(
        schema="container-audit-portable-tree-v1", version=version, source_commit=build,
    ))
    _inventory(app.parent)
    sid = "S" + "-1-5-21-" + str(int(build[:8], 16)) + "-1001"
    control = tmp_path / "update-control"
    policy = dict(operator_sid=sid, feed_url="", staging_root=str(tmp_path / "staging"))
    _write_json(control / "policy.json", policy)
    _write_json(control / "active.json", dict(schema=auto_update.SCHEMA, sha=build))
    monkeypatch.setattr(auto_update, "current_process_sid", lambda: sid)
    monkeypatch.setattr(auto_update, "ordinary_user_context", lambda *_: True)
    from tools import register_container_audit_worker_pc as registration
    monkeypatch.setattr(registration, "_current_user_sid", lambda: sid)
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(tmp_path / "business"))
    paths = onboarding.resolve_current_user_onboarding_paths(app)
    identity = _ready_state(paths)
    profile = SimpleNamespace(
        source_host_id=identity["source_host_id"], device_id=secrets.token_hex(16),
        base_url=urlunsplit(("https", catalog.AUTHENTICATED_CATALOG_HOST, "", "", "")),
        bearer_token=secrets.token_urlsafe(24), tls_ca_bundle_path="",
    )
    monkeypatch.setattr(onboarding, "_default_profile_loader", lambda _path: profile)
    monkeypatch.setattr(onboarding, "load_credentials_from_json", lambda _path: object())
    monkeypatch.setattr(onboarding, "_completed_machine_install_id", lambda: "")
    monkeypatch.setattr(user_relay, "_registry_get", lambda: user_relay.user_relay_command_line(app))
    monkeypatch.setattr(check, "_already_running", lambda _app: False)
    payload = (",".join(catalog.REQUIRED_HEADER) + "\nM06,Fixture,Spec,image.png\n").encode()
    cache = catalog.default_cache_path()
    catalog._write_authenticated_cache(
        cache, payload, url=profile.base_url + catalog.CATALOG_PATH,
        source_host_id=profile.source_host_id, device_id=profile.device_id,
        bearer_token=profile.bearer_token,
    )
    return SimpleNamespace(app=app, paths=paths, build=build, version=version, sid=sid,
                           policy=policy, control=control, cache=cache, root=tmp_path)


def _snapshot(root):
    return {path.relative_to(root).as_posix():
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
            for path in root.rglob("*")}


def _run_without_effects(installed, monkeypatch, capsys):
    before = _snapshot(installed.root)
    effects = []

    def forbidden(*_args, **_kwargs):
        effects.append(True)
        raise AssertionError("read-only startup check attempted a side effect")

    with monkeypatch.context() as blocked:
        for name in ("Popen", "run", "check_output"):
            blocked.setattr(subprocess, name, forbidden)
        blocked.setattr(socket, "socket", forbidden)
        blocked.setattr(sqlite3, "connect", forbidden)
        blocked.setattr(fence, "_acquire_named_mutex", forbidden)
        for name in ("mkdir", "unlink", "rename", "replace", "write_bytes", "write_text"):
            blocked.setattr(Path, name, forbidden)
        for name in ("mkdir", "remove", "rename", "replace", "unlink"):
            blocked.setattr(os, name, forbidden)
        result_code = check.main(["--json"], app_root=installed.app)
    output = capsys.readouterr()
    assert not output.err
    assert len(output.out.splitlines()) == 1
    assert not effects
    assert _snapshot(installed.root) == before
    assert not list(installed.root.rglob("*-wal")) + list(installed.root.rglob("*-shm"))
    return result_code, json.loads(output.out)


def test_ready_is_one_line_and_never_opens_data_or_admission(installed, monkeypatch, capsys):
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 0
    assert result["status"] == result["category"] == "READY"
    assert result["version"] == installed.version
    assert result["build_sha"] == installed.build
    assert result["categories"] == ["READY"]
    assert set(result) == {"schema", "app", "version", "build_sha", "startable", "status",
                           "reasons", "checked_at", "category", "categories"}
    assert result["checked_at"].endswith("+09:00")


@pytest.mark.parametrize("kind,category", [
    ("prepared", "UPDATE_PENDING"), ("recovery", "UPDATE_PENDING"),
    ("user_fence", "DEPLOY_FENCE"), ("machine_fence", "DEPLOY_FENCE"),
    ("version", "INSTALL_MISMATCH"), ("source_bytes", "INSTALL_MISMATCH"),
    ("relay", "INSTALL_MISMATCH"), ("account", "ACCOUNT_MISMATCH"),
    ("setup", "ACCOUNT_MISMATCH"), ("data_floor", "DATA_GUARD"),
    ("catalog", "CATALOG_OFFLINE"),
])
def test_each_existing_refusal_remains_read_only(installed, monkeypatch, capsys, kind, category):
    if kind == "prepared":
        installed.policy["feed_url"] = installed.cache.as_uri()
        _write_json(installed.control / "policy.json", installed.policy)
        _write_json(Path(installed.policy["staging_root"]) / "prepared.json",
                    {"source_commit": hashlib.sha1(b"candidate").hexdigest()})
    elif kind == "recovery":
        _write_json(installed.control / "transition.json",
                    dict(schema=auto_update.SCHEMA, phase="DEFERRED", recovery_pending=True))
    elif kind == "user_fence":
        _write_active(fence.canonical_control_root(), _active_payload(token=""))
    elif kind == "machine_fence":
        _write_json(Path(os.environ["PROGRAMDATA"]) /
                    "KMTech/ContainerAudit/machine-install/control/writer-session/active.json", {})
    elif kind == "version":
        (installed.app / "Container_Audit.py").write_text("CURRENT_VERSION = 'v2.0.101'\n", encoding="utf-8")
        _inventory(installed.app.parent)
    elif kind == "source_bytes":
        path = installed.app / "Container_Audit.py"
        path.write_bytes(path.read_bytes().replace(b"102", b"103"))
    elif kind == "relay":
        monkeypatch.setattr(user_relay, "_registry_get", lambda: "")
    elif kind == "account":
        monkeypatch.setattr(auto_update, "ordinary_user_context", lambda *_: False)
    elif kind == "setup":
        installed.paths.identity_path.unlink()
    elif kind == "data_floor":
        generation.record_generation(
            guard.marker_paths(installed.paths.data_root, installed.sid)[1],
            app_id="container_audit", subject_sid=installed.sid, version="v9.0.0",
            build_id=installed.build, data_compatible_min_version="v9.0.0",
        )
    elif kind == "catalog":
        for path in (installed.cache, catalog._cache_authority_path(installed.cache),
                     catalog._cache_recovery_path(installed.cache)):
            path.unlink()
        monkeypatch.setattr(check, "_already_running", lambda _app: True)
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 10
    assert not result["startable"]
    assert category in result["categories"]
    if kind == "catalog":
        assert "ALREADY_RUNNING" in result["categories"]


def test_recovery_catalog_and_transition_start_offline_without_writes(installed, monkeypatch, capsys):
    installed.cache.unlink()
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 0
    catalog._cache_recovery_path(installed.cache).unlink()
    monkeypatch.setattr("logistics_runtime_profile.legacy_label_transition_enabled", lambda: True)
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 0


def test_already_running_is_advisory(installed, monkeypatch, capsys):
    monkeypatch.setattr(check, "_already_running", lambda _app: True)
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 0 and result["startable"]
    assert result["category"] == "READY"
    assert result["categories"] == ["READY", "ALREADY_RUNNING"]


@pytest.mark.parametrize("operation", ["unreadable", "exception", "slow"])
def test_unknown_is_never_reported_ready_or_leaks_errors(installed, monkeypatch, capsys, operation):
    private_error = secrets.token_urlsafe(32)
    if operation == "unreadable":
        def unavailable(*_args, **_kwargs):
            raise PermissionError(private_error)
        monkeypatch.setattr(onboarding, "verify_bootstrap_integrity", unavailable)
    elif operation == "exception":
        def unavailable(*_args, **_kwargs):
            raise RuntimeError(private_error)
        monkeypatch.setattr(check, "_already_running", unavailable)
    else:
        ticks = iter([0.0])
        monkeypatch.setattr(check.time, "monotonic", lambda: next(ticks, 11.0))
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 20 and not result["startable"]
    assert "UNKNOWN" in result["categories"]
    assert bool(private_error not in json.dumps(result))


def test_bounded_inventory_never_populates_the_full_verification_cache(installed):
    before = dict(guard._PORTABLE_RELEASE_CACHE)
    assert check.check_startup(installed.app)["startable"]
    assert guard._PORTABLE_RELEASE_CACHE == before


def test_unreadable_existing_account_is_unknown(installed, monkeypatch, capsys):
    monkeypatch.setattr(onboarding, "inspect_current_user_state",
                        lambda *_args, **_kwargs: {"status": "RECOVERY_REQUIRED", "error_type": "PermissionError"})
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 20 and "UNKNOWN_ACCOUNT" in result["reasons"]


@pytest.mark.parametrize("missing", ["bootstrap-integrity.json", "portable-manifest.json"])
def test_missing_installation_record_is_a_known_mismatch(installed, monkeypatch, capsys, missing):
    (installed.app.parent / missing).unlink()
    code, result = _run_without_effects(installed, monkeypatch, capsys)
    assert code == 10 and "INSTALL_MISMATCH" in result["categories"]


def test_isolated_entrypoint_imports_no_gui_and_has_no_write_attempts(tmp_path):
    script = r'''
import sys, json, os
from pathlib import Path
sys.dont_write_bytecode = True
sys.path[:0] = [sys.argv[1], str(Path(sys.argv[1]) / "site-packages")]
attempted = []
class NoGui:
    def find_spec(self, fullname, *_args):
        if fullname.split(".")[0] in {"tkinter", "Container_Audit"}:
            attempted.append("GUI import")
            raise AssertionError("GUI import attempted")
sys.meta_path.insert(0, NoGui())
def readonly(event, args):
    if event in {"os.mkdir", "os.remove", "os.rename", "os.rmdir", "subprocess.Popen",
                 "sqlite3.connect", "socket.__new__", "socket.connect", "socket.getaddrinfo"}:
        attempted.append(event)
        raise AssertionError("side effect attempted")
    if event == "open" and isinstance(args[2], int) and args[2] & (
            os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        attempted.append("write")
        raise AssertionError("write attempted")
sys.addaudithook(readonly)
import startup_check
import writer_session_fence
def deny(*_args, **_kwargs):
    attempted.append("writer admission")
    raise AssertionError("writer admission attempted")
writer_session_fence.writer_admission = deny
writer_session_fence._acquire_named_mutex = deny
exit_code = startup_check.main(["--json"])
assert not attempted
raise SystemExit(exit_code)
'''
    completed = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT)],
                               cwd=tmp_path, capture_output=True, text=True, timeout=15)
    assert completed.returncode in {10, 20}
    assert not completed.stderr
    assert len(completed.stdout.splitlines()) == 1
    result = json.loads(completed.stdout)
    assert result["schema"] == "app_startup_check.v1" and result["app"] == "CA"
    assert "UNKNOWN_CHECK" not in result["reasons"]


@pytest.mark.parametrize("phase,prepared,recovery,expected", [
    (None, False, False, False), (None, True, False, True),
    ("CONFIRMED", False, False, False), ("ROLLED_BACK", False, False, False),
    ("DEFERRED", False, False, False), ("DEFERRED", False, True, True),
    ("PREPARED", False, False, True), ("FAILED", False, False, True),
    ("UNKNOWN", False, False, True), ("APPLIED_PENDING_READY", False, False, True),
])
def test_shared_ordinary_startup_decision(installed, phase, prepared, recovery, expected):
    state = None if phase is None else dict(phase=phase, recovery_pending=recovery)
    assert auto_update.startup_requires_bootstrap(
        state, prepared_present=prepared, running_sha=installed.build,
        active_sha=installed.build) is expected


def test_native_process_observation_has_no_children_or_mutexes(tmp_path, monkeypatch):
    effects = []

    def forbidden(*_args, **_kwargs):
        effects.append(True)
        raise AssertionError("process observer attempted a mutation")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(fence, "_acquire_named_mutex", forbidden)
    try:
        assert not check._already_running(tmp_path / "app")
    except OSError:
        pytest.skip("native process visibility is unavailable to this session")
    assert not effects

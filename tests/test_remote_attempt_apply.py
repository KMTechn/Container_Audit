import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading

import pytest
import requests
import item_catalog_sync as catalog
from storage_utils import RemoteAttempt
from test_item_catalog_sync import CATALOG, UNAUTHENTICATED_OVERRIDE_URL
from tools import register_container_audit_worker_pc as registration


def test_attempt_generation_is_durable_across_processes(tmp_path):
    owner = tmp_path / "owner.json"
    first = RemoteAttempt.begin(owner, "cross_process")
    different = RemoteAttempt.begin(tmp_path / "other.json", "cross_process")
    subprocess.run([sys.executable, "-B", "-c", "import sys; from storage_utils import RemoteAttempt; RemoteAttempt.begin(sys.argv[1], 'cross_process')", str(owner)],
        check=True, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with first.apply() as current:
        assert current is False
    with different.apply() as current:
        assert current is True


@pytest.mark.parametrize("old_success", [False, True])
def test_catalog_old_response_preserves_new_failure_diagnostics(tmp_path, monkeypatch, ca_remote_lock_guard, old_success):
    bundled, cache = tmp_path / "bundled.csv", tmp_path / "cache.csv"
    bundled.write_bytes(CATALOG)
    monkeypatch.setattr(catalog, "_load_item_catalog_logistics_profile", lambda *_args: None)
    entered, release = threading.Event(), threading.Event()
    failures = []
    class Response:
        status_code = 200
        reason = "OK"
        content = CATALOG
        def raise_for_status(self): pass
    def old_get(*_args, **_kwargs):
        entered.set()
        assert release.wait(10)
        if old_success: return Response()
        raise requests.ConnectionError("older synthetic failure")
    def old_work():
        try:
            catalog.refresh_item_catalog(bundled, cache_path=cache, url=UNAUTHENTICATED_OVERRIDE_URL,
                get=ca_remote_lock_guard.wrap_transport(old_get, label="catalog old GET"))
        except BaseException as exc: failures.append(exc)
    thread = threading.Thread(target=old_work)
    thread.start()
    assert entered.wait(5)
    def new_get(*_args, **_kwargs): raise requests.Timeout("newest synthetic timeout")
    try:
        catalog.refresh_item_catalog(bundled, cache_path=cache, url=UNAUTHENTICATED_OVERRIDE_URL,
            get=ca_remote_lock_guard.wrap_transport(new_get, label="catalog new GET"))
        expected = catalog.get_catalog_attempt_context()
        assert expected["exception_type"] == "Timeout"
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive() and not failures
    assert not cache.exists()
    assert catalog.get_catalog_attempt_context() == expected


@pytest.mark.parametrize("old_success", [False, True])
def test_registration_old_response_preserves_new_failure_report(tmp_path, monkeypatch, ca_remote_lock_guard, old_success):
    entered, release = threading.Event(), threading.Event()
    invocation = 0
    report = tmp_path / "report.json"
    class Response:
        status_code = 200
    def post(_self, _url, **kwargs):
        if kwargs["json"]["ordinal"] == 1:
            entered.set()
            assert release.wait(10)
            if not old_success: raise requests.ConnectionError("older synthetic failure")
        return Response()
    monkeypatch.setattr(requests.Session, "post", ca_remote_lock_guard.wrap_transport(post, label="registration held POST"))
    def build(args):
        nonlocal invocation
        invocation += 1
        ordinal = invocation
        args._registration_attempt = RemoteAttempt.begin(tmp_path / "identity.json", "worker_registration")
        registration._post_enrollment_request("https://worker.example.invalid/enroll",
            json={"ordinal": ordinal}, headers={}, timeout=30, allow_redirects=False, verify=True,
            attempt=args._registration_attempt)
        if ordinal == 2: raise registration.DirectSyncPushError("newest synthetic failure")
        return {"source": "old"}, {"source": "old"}, {}
    monkeypatch.setattr(registration, "build_registration_payloads", build)
    options = ["--app-root", str(tmp_path / "code"), "--manifest-path", str(tmp_path / "manifest.json"),
        "--credential-path", str(tmp_path / "credential.json"), "--report-path", str(report)]
    answers, failures = [], []
    def old_work():
        try: answers.append(registration.main(options))
        except BaseException as exc: failures.append(exc)
    thread = threading.Thread(target=old_work)
    thread.start()
    assert entered.wait(5)
    try:
        assert registration.main(options) == 2
        expected = hashlib.sha256(report.read_bytes()).hexdigest()
        assert json.loads(report.read_bytes())["blocked_reason"] == "newest synthetic failure"
    finally:
        release.set()
        thread.join(10)
    assert not thread.is_alive() and not failures and answers == [2]
    assert hashlib.sha256(report.read_bytes()).hexdigest() == expected
    assert not (tmp_path / "manifest.json").exists() and not (tmp_path / "credential.json").exists()

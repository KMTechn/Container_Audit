"""Real delayed enrollment through public wrappers and late owner changes."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest
import requests

from tests.test_scan_persistence_lane import ITEM, app, pump
from tests.test_worker_pc_registration import registration_possession_key_contract, _v2_response_binding
from tests.test_direct_sync_relay_operator import (
    _acked_restore_case, RestoreResponse, RestoreSession,
    _isolate_operator_contract_tests_from_runtime_lease,
)
from tk_serial_ui_lane import LaneTask
from tools import register_container_audit_worker_pc as registration
import current_user_onboarding as onboarding
import direct_sync_operator


@pytest.mark.parametrize("entry", ["main", "onboarding", "startup"])
@pytest.mark.parametrize("delay", [0.3, 6, 35])
def test_scan_durable_during_public_enrollment_wrappers(
    app, tmp_path, monkeypatch, registration_possession_key_contract, entry, delay,
):
    app.current_tray.tray_size = 6
    app.scan_entry.insert("end", ITEM + "-enroll-0")
    app.process_barcode()
    pump(app, lambda: len(app.current_tray.scanned_barcodes) == 1 and not app._ui_lane.is_busy())
    entered = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            entered.set()
            time.sleep(delay)
            result = {**_v2_response_binding(), "status": "enrolled",
                "producer_id": payload["producer_id"], "key_id": payload["key_id"],
                "secret": "synthetic-enrollment", "active_manifest_hashes": [registration.manifest_hash(payload["manifest"])]}
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    raw_session = requests.Session
    class LoopbackSession(raw_session):
        def request(self, method, url, **kwargs):
            assert url.startswith("https://worker.example.invalid/")
            url = url.replace("https://worker.example.invalid", f"http://127.0.0.1:{server.server_port}", 1)
            return super().request(method, url, **kwargs)

    monkeypatch.setattr(requests, "Session", LoopbackSession)
    monkeypatch.setattr(registration, "_write_wincred_secret", lambda *_args: None)
    root = tmp_path / "enrollment"
    root.mkdir()
    manifest_path, credential_path = root / "manifest.json", root / "credential.json"
    options = ["--self-enroll", "--secret-ref", "wincred:synthetic-enrollment",
        "--enrollment-timeout-seconds", "60",
        "--endpoint-url", "https://worker.example.invalid/api/producer-ingest/v1/source-file",
        "--manifest-path", str(manifest_path), "--credential-path", str(credential_path),
        "--report-path", str(root / "registration.json")]

    def ledger(path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic ledger")

    def onboard(_app_root, **_kwargs):
        return onboarding.onboard_current_user(
            tmp_path.parent / (tmp_path.name + "-code"), require_bootstrap_integrity=False,
            registration_runner=lambda _paths: registration.main(options),
            ledger_factory=ledger,
            autostart_installer=lambda *_args, **_kwargs: {"status": "PASS"},
            relay_launcher=lambda *_args, **_kwargs: {"status": "START_REQUESTED"},
        )

    monkeypatch.setattr(onboarding, "inspect_current_user_state",
        lambda *_args, **_kwargs: {"status": "READY" if credential_path.exists() else "ABSENT"})
    monkeypatch.setattr(onboarding, "verify_bootstrap_integrity", lambda *_args, **_kwargs: {"status": "PASS"})
    work = lambda: registration.main(options)
    if entry == "onboarding":
        work = lambda: onboard(tmp_path / "code")
    elif entry == "startup":
        import Container_Audit as gui
        monkeypatch.setattr(gui, "verify_factory_contract_startup", lambda: None)
        monkeypatch.setattr(gui, "acquire_runtime_instance", lambda _root: SimpleNamespace(release=lambda: None))
        monkeypatch.setattr(gui, "_first_run_onboarding_enabled", lambda: True)
        monkeypatch.setattr(gui, "onboard_current_user", onboard)
        monkeypatch.setattr(gui, "prepare_startup_item_catalog", lambda: None)
        class StartupApp(gui.ContainerAudit):
            def __init__(self):
                self.root = SimpleNamespace(after=lambda *_args: None)
        monkeypatch.setattr(gui, "ContainerAudit", StartupApp)
        work = lambda: gui._prepare_gui_startup(data_root=app.save_folder)

    failures, answers = [], []
    app.current_tray.tray_size = 6
    lane = app._scanonly_transport_lane()
    assert lane.submit(LaneTask(name="public-enrollment", generation=app._scan_callback_epoch,
        work=work, finish=answers.append, fail=failures.append)).accepted
    try:
        pump(app, lambda: entered.is_set() or failures or answers)
        assert entered.is_set(), {"errors": [str(error) for error in failures], "answers": [answer if isinstance(answer, int) else type(answer).__name__ for answer in answers]}
        started = time.monotonic()
        for index in (1, 2):
            app.scan_entry.insert("end", ITEM + f"-enroll-{index}")
            app.process_barcode()
            pump(app, lambda: not app._ui_lane.is_busy() and app.scan_entry.get() == "")
        saved = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text())
        elapsed = time.monotonic() - started
        assert saved["scanned_barcodes"] == [ITEM + "-enroll-0", ITEM + "-enroll-1", ITEM + "-enroll-2"]
        assert app.scan_entry.state == "normal" and elapsed < 1
        assert not answers and not failures
        print(json.dumps({"enrollment_entry": entry, "delay": delay, "scan_durable_seconds": elapsed}))
    finally:
        app.root.run_until(lambda: not lane.is_busy() if time.sleep(0.002) is None else False, timeout=delay + 10)
        server.shutdown()
        server.server_close()
        server_thread.join()
    assert not failures and answers
    if entry == "main":
        assert answers[0] == 0
    elif entry == "onboarding":
        assert answers[0]["status"] == "READY"
    else:
        assert isinstance(answers[0], tuple)
    assert manifest_path.is_file() and credential_path.is_file()


@pytest.mark.parametrize("changed_field", ["status", "metadata_json", "producer_id"])
def test_operator_restore_rechecks_acked_owner_before_publish(tmp_path, changed_field):
    config, relay_id, credentials, destination = _acked_restore_case(tmp_path / "restore")
    body = destination.read_bytes()
    destination.unlink()
    class ChangingSession(RestoreSession):
        def get(self, *args, **kwargs):
            with sqlite3.connect(config.db_path) as conn:
                conn.execute(f"UPDATE direct_sync_relay_batches SET {changed_field} = ? WHERE relay_id = ?",
                             ("changed", relay_id))
            return super().get(*args, **kwargs)

    session = ChangingSession(RestoreResponse(200, body, headers={
        "X-Content-SHA256": hashlib.sha256(body).hexdigest(), "X-Byte-Length": str(len(body))}))
    audit = tmp_path / "operator.jsonl"
    report = direct_sync_operator.restore_relay_spool_from_server(
        db_path=config.db_path, relay_id=relay_id, spool_root=config.spool_dir,
        credentials=credentials, operator_id="fixture", reason="restore", audit_log_path=audit, session=session,
    )
    assert report["status"] == "BLOCKED" and report["error_code"] == "restore_source_changed"
    assert not destination.exists()
    assert "restore-spool-blocked" in audit.read_text()


@pytest.mark.parametrize("delay", [0.3, 6, 35])
def test_public_scan_stays_durable_during_operator_restore(app, tmp_path, delay):
    app.current_tray.tray_size = 6
    app.scan_entry.insert("end", ITEM + "-restore-first")
    app.process_barcode()
    pump(app, lambda: len(app.current_tray.scanned_barcodes) == 1 and not app._ui_lane.is_busy())
    config, relay_id, credentials, destination = _acked_restore_case(tmp_path / "restore")
    body = destination.read_bytes()
    destination.unlink()
    entered = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            entered.set()
            time.sleep(delay)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-SHA256", hashlib.sha256(body).hexdigest())
            self.send_header("X-Byte-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # The 35s case preserves the product's 30s transport timeout.
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    class LoopbackSession(requests.Session):
        def request(self, method, url, **kwargs):
            assert url.startswith("https://")
            from urllib.parse import urlsplit
            return super().request(method, f"http://127.0.0.1:{server.server_port}" + urlsplit(url).path, **kwargs)
    session = LoopbackSession()
    session.trust_env = False
    answers, failures = [], []
    lane = app._scanonly_transport_lane()
    assert lane.submit(LaneTask(name="operator-restore", generation=app._scan_callback_epoch,
        work=lambda: direct_sync_operator.restore_relay_spool_from_server(
            db_path=config.db_path, relay_id=relay_id, spool_root=config.spool_dir,
            credentials=credentials, operator_id="fixture", reason="restore", session=session),
        finish=answers.append, fail=failures.append)).accepted
    try:
        pump(app, lambda: entered.is_set() or failures or answers)
        assert entered.is_set() and not failures
        started = time.monotonic()
        app.scan_entry.insert("end", ITEM + "-restore-second")
        app.process_barcode()
        pump(app, lambda: len(app.current_tray.scanned_barcodes) == 2 and not app._ui_lane.is_busy())
        elapsed = time.monotonic() - started
        saved = json.loads((Path(app.save_folder) / app.CURRENT_TRAY_STATE_FILE).read_text())
        assert ITEM + "-restore-second" in saved["scanned_barcodes"] and elapsed < 1
        assert not answers and not destination.exists()
        print(json.dumps({"operator_restore_delay": delay, "scan_durable_seconds": elapsed}))
    finally:
        app.root.run_until(lambda: not lane.is_busy() if time.sleep(0.002) is None else False, timeout=delay + 10)
        session.close()
        server.shutdown()
        server.server_close()
        thread.join()
    assert not failures
    if delay < 30:
        assert answers[0]["status"] == "PASS" and destination.read_bytes() == body
    else:
        assert answers[0]["status"] == "BLOCKED" and answers[0]["restore_retryable"] is True
        assert not destination.exists()
        with sqlite3.connect(config.db_path) as conn:
            assert conn.execute("SELECT status FROM direct_sync_relay_batches WHERE relay_id = ?", (relay_id,)).fetchone()[0] == "acked"


def test_registration_refuses_late_owner_change_before_profile_or_key_write(tmp_path, monkeypatch):
    args = SimpleNamespace(_registration_artifact_paths=(tmp_path / "identity.json",))
    args._registration_expected_artifacts = registration._registration_artifact_versions(args)
    args._registration_artifact_paths[0].write_text('{"owner":"newer"}')
    def forbidden(*_args, **_kwargs):
        raise AssertionError("late response must be refused before credential access/write")
    monkeypatch.setattr(registration.PersistentPossessionKey, "open_existing", forbidden)
    with pytest.raises(registration.EnrollmentAdminRecoveryRequired) as error:
        registration._finalize_server_registration(args, {}, {}, "dpapi", "fixture", response_payload={},
            registration_url="https://fixture.invalid", registration_contract_version="fixture", token="",
            authority_ca_bundle_path="", configured_ca_bundle_path="", enrollment_ca_bundle_path="",
            possession_descriptor=None, non_exportability=None)
    assert error.value.error_code == "registration_owner_state_changed"
    assert args._registration_artifact_paths[0].read_text() == '{"owner":"newer"}'


@pytest.mark.parametrize("action", ["transition", "package"])
def test_recovery_response_cannot_apply_to_another_owner(tmp_path, action):
    from recovery_two_phase import RecoveryTwoPhaseJournal, RecoveryTwoPhaseStateError
    from tests.test_recovery_two_phase import _bindings
    journal = RecoveryTwoPhaseJournal(tmp_path / "journal.json")
    journal.initialize(_bindings())
    current = journal.load()
    current["bindings"] = _bindings("newer")
    journal.path.write_text(json.dumps(current))
    before = journal.path.read_bytes()
    with pytest.raises(RecoveryTwoPhaseStateError, match="owner changed"):
        if action == "transition":
            journal.record_prepared(prepare_id="old", prepare_expires_at="2999-01-01T00:00:00Z",
                proposed_credential_epoch=2, prepared_key_id="fixture", prepared_secret_fingerprint_sha256="b" * 64)
        else:
            journal.stage_sealed_package(b"old-package")
    assert journal.path.read_bytes() == before and not journal.sealed_package_path.exists()

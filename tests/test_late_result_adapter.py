import json
import hashlib
import queue
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest
import requests
import direct_sync_push as relay
import direct_sync_runtime as runtime
from test_direct_sync_runtime import _isolate_legacy_runtime_tests_from_runtime_lease
from late_result_guard import (AuditEvent, AuditKind, DrainResult, LocalState,
    REQUIRED_SCENARIOS, ResultKind, Snapshot, run_late_result_scenarios)
from test_direct_sync_push import (FakeResponse, legacy_relay_without_runtime_lease,
    make_credentials, make_manifest, write_csv)


class RelayLateAdapter:
    late_success_policy = None  # This drain keeps uncertain late success for operator review.

    def __init__(self, root, transport, guard):
        self.root, self.transport, self.guard = root, transport, guard
        root.mkdir()
        self.db = root / "queue.db"
        _, manifest = make_manifest(root)
        self.config = runtime.DirectSyncRuntimeConfig(db_path=self.db, spool_dir=root / "spool", producer_manifest_path=manifest, credential_path=root / "unused.json", upload_status_dir=root / "status", runtime_status_path=root / "runtime.json", log_path=root / "runtime.jsonl")
        self.credentials = make_credentials()
        self.now = datetime.now(timezone.utc)
        self.jobs = {}
        self.received = queue.Queue()
        self.created = 0

    def row(self, command):
        with sqlite3.connect(self.db) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM direct_sync_relay_batches WHERE relay_id=?", (command,)).fetchone())

    def create_command(self, label):
        self.created += 1
        root = self.root / str(self.created)
        root.mkdir()
        _, manifest = make_manifest(root)
        return relay.enqueue_source_file_for_relay(db_path=self.db,
            spool_dir=self.root / "spool", source_file_path=write_csv(root),
            producer_manifest_path=manifest, credentials=self.credentials, relative_path=f"command{self.created}/source.csv").relay_id

    def session(self):
        adapter = self
        class Session:
            def post(self, url, *, data, files, headers, timeout, allow_redirects):
                metadata = json.loads(data["metadata"])
                command = metadata["client_batch_id"]
                captured = adapter.transport.hold(command, adapter.row(command)["attempt_count"])
                adapter.received.put(captured)
                result = adapter.transport.wait(captured, timeout=30)
                if result == ResultKind.TIMEOUT:
                    raise requests.Timeout("synthetic held timeout")
                if result == ResultKind.DISCONNECT:
                    raise requests.ConnectionError("synthetic held disconnect")
                if result == ResultKind.SUCCESS:
                    return FakeResponse(200, dict(committed=True, retryable=False,
                        request_id="synthetic-receipt", upload_id="synthetic-receipt",
                        client_batch_id=command,
                        server_source_file_id=relay._expected_server_source_file_id(metadata),
                        status="accepted", projection_disposition="COMPLETE", error=None,
                        next_retry_after=None, totals=dict(inserted=metadata["row_count"],
                        replayed=0, errors=0, quarantined=0)))
                retry = result == ResultKind.RETRY_FAILURE
                return FakeResponse(503 if retry else 400, dict(committed=False,
                    retryable=retry, error=dict(code="shared_retry" if retry else "shared_nonretry")))
        session = Session()
        session.post = self.guard.wrap_transport(session.post, label="shared relay POST")
        return session

    def start_attempt(self, command):
        self.now = max(self.now, datetime.now(timezone.utc))
        errors = []
        def work():
            try:
                runtime.run_relay_once(self.config, credentials=self.credentials,
                    session=self.session(), target_relay_id=command,
                    now=self.now.replace(microsecond=0).isoformat().replace("+00:00", "Z"))
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=work)
        thread.start()
        try:
            captured = self.received.get(timeout=10)
        except queue.Empty:
            thread.join(1)
            if errors:
                raise errors[0]
            raise AssertionError({"status": self.row(command)["status"], "attempt": self.row(command)["attempt_count"]})
        self.jobs[captured] = (thread, errors)
        return captured

    def expire_attempt(self, attempt):
        # Advance only the supported API's 'now' input past the actual stored expiry.
        # Do not rewrite result/lease rows or alter the process clock.
        expires = datetime.fromisoformat(self.row(attempt.command)["lease_expires_at"].replace("Z", "+00:00"))
        self.now = max(self.now, expires + timedelta(seconds=1))
        assert relay.reset_stale_relay_leases(db_path=self.db, now=self.now.replace(microsecond=0).isoformat().replace("+00:00", "Z")) == 1

    def deliver(self, attempt, result):
        stale = self.row(attempt.command)["attempt_count"] > attempt.number
        before = self.diagnostics()
        self.transport.release(attempt, result)
        thread, errors = self.jobs[attempt]
        thread.join(10)
        assert not thread.is_alive()
        if errors:
            raise errors[0]
        if stale:
            assert self.diagnostics() == before

    def diagnostics(self):
        paths = [self.root / "runtime.json", self.root / "runtime.jsonl"]
        paths.extend((self.root / "status").glob("direct_sync_upload_status_*.json"))
        return tuple(sorted((str(path), hashlib.sha256(path.read_bytes()).hexdigest()) for path in paths if path.exists()))

    def snapshot(self, command):
        row = self.row(command)
        state = {relay.RELAY_STATUS_ACKED: LocalState.COMPLETE,
            relay.RELAY_STATUS_LEASED: LocalState.SENDING,
            relay.RELAY_STATUS_PENDING: LocalState.PENDING,
            relay.RELAY_STATUS_RETRY_WAIT: LocalState.PENDING,
            relay.RELAY_STATUS_OPERATOR_REVIEW: LocalState.NEEDS_REVIEW,
            relay.RELAY_STATUS_FAILED_PERMANENT: LocalState.NEEDS_REVIEW}[row["status"]]
        reason = None
        if row["last_error_code"]:
            if row["last_error_code"] == "shared_retry": reason = ResultKind.RETRY_FAILURE
            elif row["last_error_code"] == "shared_nonretry": reason = ResultKind.NONRETRY_FAILURE
            else:
                # The native transport result distinguishes timeout and disconnect.
                reason = self.transport.outcome(next(a for a in self.jobs if a.command == command and a.number == row["attempt_count"]))
        return Snapshot(state, row["attempt_count"], reason)

    def audit(self, command):
        row = self.row(command)
        state = self.snapshot(command)
        return (AuditEvent(state.attempt, AuditKind.FAILURE, state.reason),) if row["last_error_code"] else ()

    def central_effects(self, command): return self.transport.central_effects(command)
    def request_count(self, command): return self.transport.request_count(command)

    def background_once(self):
        result = relay.drain_one_relay_batch(db_path=self.db, credentials=self.credentials,
            session=self.session(), now=self.now.replace(microsecond=0).isoformat().replace("+00:00", "Z"))
        return DrainResult(int(result is not None), False)

    def reconcile(self, command):
        raise AssertionError("this drain does not declare receipt reconciliation")

    def close(self):
        for attempt, (thread, _) in self.jobs.items():
            if self.transport.outcome(attempt) is None:
                self.transport.release(attempt, ResultKind.DISCONNECT)
            thread.join(10)
            assert not thread.is_alive()


@pytest.mark.usefixtures("legacy_relay_without_runtime_lease")
@pytest.mark.parametrize("scenario", REQUIRED_SCENARIOS)
def test_shared_late_results_through_real_relay(ca_late_result_adapter_factory, scenario):
    run_late_result_scenarios(ca_late_result_adapter_factory, scenario)

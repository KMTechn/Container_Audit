"""w9cap1fix: unsent completions go out in the background, the screen says they
wait, lease time checks allow the server's clock tolerance, and an abandoned
tray gives its unused lease back (P1-2, P1-5, P1-3 CA part)."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
import threading
from types import SimpleNamespace

import pytest
import requests

import Container_Audit as container_module
from Container_Audit import ContainerAudit, TraySession
from direct_sync_health import RelayHealth, relay_health_card_model
from terminal_operation_lease import (
    LEASE_BINDING_KEYS,
    OperationLeaseError,
    utc_text,
    validate_artifact,
)
from tests.operation_lease_fixtures import (
    FIXED_LEASE_NOW,
    fixed_operation_lease_clock,  # noqa: F401 - fixture
    signed_transfer_artifact,
)
from tests.test_container_p0_contracts import _startup_transfer_recovery_app
from tests.test_phs2_master_preflight import (
    BlockingClient,
    COMPACT_QR,
    ITEM,
    _app,
    _pump_until,
    _resolved,
)
from transfer_seal import TransferSealCoordinator, TransferSealStore
from warning_presenter import (
    CompletionOutcome,
    CompletionOutcomeSnapshot,
    notice_for_completion,
)

BACKGROUND_MS = 30_000
REQUERY_MS = 3_000
LEASE_ID = "operation-lease-fixture-01"


class _Server:
    """Logistics transport stand-in that does not answer until ``up``."""

    def __init__(self):
        self.up = False
        self.limits = []
        self._local = threading.local()

    @contextmanager
    def bounded_wait(self, seconds):
        self.limits.append(seconds)
        previous = getattr(self._local, "unanswered", False)
        self._local.unanswered = False
        try:
            yield
        finally:
            self._local.unanswered = previous

    def server_unanswered(self):
        return bool(getattr(self._local, "unanswered", False))

    def no_answer(self):
        self._local.unanswered = True


def _background_app(tmp_path, *, intents):
    server = _Server()
    app, root, lane, hold_store, seal_store, _member_store, calls = (
        _startup_transfer_recovery_app(tmp_path, seal_intent_ids=intents)
    )
    seal_store.has_exact_history = lambda: True
    coordinator = app.transfer_seal_coordinator
    coordinator.client = server

    def attempt(intent_id):
        calls["seal"].append((intent_id, threading.get_ident()))
        if not server.up:
            server.no_answer()
            return SimpleNamespace(
                status="RETRY_WAIT", intent_id=intent_id, error_code="TRANSPORT_ERROR"
            )
        seal_store.intent_ids.remove(intent_id)
        return SimpleNamespace(status="ACKED", intent_id=intent_id, error_code="")

    coordinator.attempt = attempt
    return app, root, lane, hold_store, seal_store, calls, server


def _background_jobs(root):
    return [job for job in root.jobs if job[1] == BACKGROUND_MS]


def _close(root, lane):
    if lane.state != "CLOSED":
        lane.close_idle()
        root.run_until(lambda: lane.state == "CLOSED")


def test_pending_seal_intent_is_sent_in_background_after_the_server_returns(tmp_path):
    app, root, lane, _hold, seal_store, calls, server = _background_app(
        tmp_path, intents=("seal-1",)
    )
    try:
        # The only recovery of this run meets a stopped server; no completion
        # or restart follows.
        assert app._schedule_startup_transfer_recovery() is True
        root.run_until(lambda: not lane.is_busy() and bool(_background_jobs(root)))
        assert seal_store.intent_ids == ["seal-1"]
        assert app._pending_seal_intent_count == 1

        server.up = True
        root.run_until(lambda: seal_store.intent_ids == [] and not lane.is_busy())
        assert [intent for intent, _thread in calls["seal"]] == ["seal-1", "seal-1"]
        assert all(thread == lane.worker_thread_id for _intent, thread in calls["seal"])
        assert app._pending_seal_intent_count == 0
        assert _background_jobs(root) == []
    finally:
        _close(root, lane)


def test_background_seal_retry_waits_while_a_hold_blocks_mutation(tmp_path):
    app, root, lane, hold_store, seal_store, calls, server = _background_app(
        tmp_path, intents=("seal-1",)
    )
    try:
        assert app._schedule_startup_transfer_recovery() is True
        root.run_until(lambda: not lane.is_busy() and bool(_background_jobs(root)))
        server.up = True
        hold_store.start(worker="tester", master_raw="MASTER", scan_epoch=2)
        root.run_until(
            lambda: app._startup_transfer_recovery_waiting_for_hold
            and not lane.is_busy()
        )
        assert len(calls["seal"]) == 1
        assert seal_store.intent_ids == ["seal-1"]

        # The hold's own release schedules the recovery that sends it.
        assert hold_store.mark_draining() is None
        app._preflight_hold_snapshot = None
        app._preflight_hold_draining = False
        app._preflight_completion_due = False
        app._update_action_button_states = lambda: None
        app._complete_after_preflight_hold_drain()
        root.run_until(lambda: seal_store.intent_ids == [] and not lane.is_busy())
        assert [intent for intent, _thread in calls["seal"]] == ["seal-1", "seal-1"]
    finally:
        _close(root, lane)


def test_background_seal_retry_shares_the_completion_wait_limit(tmp_path):
    app, root, lane, _hold, seal_store, calls, server = _background_app(
        tmp_path, intents=("seal-1", "seal-2")
    )
    try:
        assert app._schedule_startup_transfer_recovery() is True
        root.run_until(lambda: not lane.is_busy() and bool(_background_jobs(root)))
        # Restart recovery is unchanged: every pending intent, no shared limit.
        assert [intent for intent, _thread in calls["seal"]] == ["seal-1", "seal-2"]
        assert server.limits == []

        job = _background_jobs(root)[0]
        root.jobs.remove(job)
        job[2](*job[3])
        root.run_until(lambda: not lane.is_busy() and bool(_background_jobs(root)))
        assert server.limits == [ContainerAudit.COMPLETION_SERVER_WAIT_SECONDS]
        # FIFO stops at the first intent the server left unanswered.
        assert [intent for intent, _thread in calls["seal"][2:]] == ["seal-1"]
        assert seal_store.intent_ids == ["seal-1", "seal-2"]
    finally:
        _close(root, lane)


class _Label(dict):
    def winfo_exists(self):
        return True

    def configure(self, **kwargs):
        self.update(kwargs)


def test_retry_wait_completion_text_says_waiting():
    snapshot = CompletionOutcomeSnapshot(
        outcome=CompletionOutcome.LINKED,
        item_name="fixture item",
        master_label=COMPACT_QR,
        scan_count=2,
        target_count=2,
        message="fixture",
    )
    notice = notice_for_completion(snapshot)
    assert "완료" not in notice.title
    assert notice.title == "서버 전송 대기"
    assert "자동으로 다시 보냅니다" in notice.message

    app = ContainerAudit.__new__(ContainerAudit)
    app.current_tray = TraySession()
    app.master_label_replace_state = None
    app.current_item_label = _Label()
    app.notice_title_label = _Label()
    app.notice_message_label = _Label()
    status_value = _Label()
    app.info_cards = {"status": {"value": status_value}}
    for name in ("COLOR_TEXT", "COLOR_SUCCESS", "COLOR_IDLE", "COLOR_DANGER"):
        setattr(app, name, name)
    app._schedule_notice_message_wrap_refresh = lambda **kwargs: None
    app._pending_seal_intent_count = 2
    app._warning_state_presenter().present_completion(snapshot)
    app._render_warning_state()
    assert app.notice_title_label["text"] == "서버 전송 대기 2건(자동으로 다시 보냄)"
    assert status_value["text"] == "서버 전송 대기 2건"

    # The 저장 전송 card counts stored completions, not only the event queue.
    health = RelayHealth(
        state="ready",
        pending_count=0,
        failed_permanent_count=0,
        operator_review_count=0,
        last_acked_at="",
        oldest_pending_at="",
        observed_at="",
    )
    card = relay_health_card_model(health, transfer_pending_count=2)
    assert card["summary"] == "완료 전송 대기 2건"
    assert card["detail"] == "자동으로 다시 보냄"
    assert relay_health_card_model(health)["summary"] == "전송 대기 없음"


class _LeaseServer(BlockingClient):
    """Issues one stable lease per issue key (server replay) and releases it."""

    def __init__(self, *, issued_at=None):
        super().__init__(_resolved(count=2))
        self.issued_at = issued_at
        self.up = True
        self.lease_status = "ACTIVE"
        self.artifacts = {}
        self.releases = []
        self._wait = _Server()

    def issue_operation_lease(self, **kwargs):
        self.identities.append(dict(kwargs))
        key = kwargs["idempotency_key"]
        if key not in self.artifacts:
            self.artifacts[key], _claims = signed_transfer_artifact(
                self.response,
                scan_payload=kwargs["scan_payload"],
                issued_at=self.issued_at,
            )
        return dict(self.artifacts[key], status=self.lease_status)

    def bounded_wait(self, seconds):
        return self._wait.bounded_wait(seconds)

    def server_unanswered(self):
        return self._wait.server_unanswered()

    def release_operation_lease(self, **kwargs):
        self.releases.append(dict(kwargs))
        if not self.up:
            self._wait.no_answer()
            raise requests.ConnectionError("server stopped")
        self.lease_status = "RELEASED"
        return {
            "contract_version": "terminal-operation-lease-release-v1",
            "lease_id": LEASE_ID,
            "status": "RELEASED",
            "fence": 1,
            "resolution": "DEVICE_RELEASED_UNUSED",
            "reason": kwargs["reason"],
            "released_at": utc_text(FIXED_LEASE_NOW),
            "replayed": len(self.releases) > 1,
        }


def _scan_label(app):
    app._process_barcode_logic(COMPACT_QR)
    _pump_until(
        app.root,
        lambda: bool(app.current_tray.master_label_code)
        and not app._preflight_context_blocks_mutation(),
    )


def _reset(app, monkeypatch):
    monkeypatch.setattr(container_module.messagebox, "askyesno", lambda *a, **k: True)
    for name in (
        "_phs_label_exchange_blocks_tray_transition",
        "_transfer_member_exchange_blocks_local_action",
    ):
        setattr(app, name, lambda *_args: False)
    app._log_cancel_event = lambda *args, **kwargs: True
    app._stop_stopwatch = app._stop_idle_checker = lambda: None
    app.scanned_listbox = SimpleNamespace(delete=lambda *args: None)
    app.undo_button = {}
    for name in (
        "_sync_last_normal_scan_from_active_tray",
        "_update_all_summaries",
        "_reset_ui_to_waiting_state",
    ):
        setattr(app, name, lambda *args, **kwargs: None)
    app._drain_phs_replacement_waiting_projections = lambda: None
    _settle(app)
    app.reset_current_work()
    assert app.current_tray.master_label_code == "", app.statuses[-2:]


def _settle(app):
    _pump_until(app.root, lambda: not app._ui_task_lane().is_busy())


def _attempt_status(app):
    manager = app.transfer_seal_coordinator.operation_lease_manager
    return manager.store.issue_attempt_for_lease(LEASE_ID)["status"]


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_lease_issued_one_second_ahead_of_pc_clock_is_accepted(tmp_path):
    issued = FIXED_LEASE_NOW + timedelta(seconds=1)
    artifact, claims = signed_transfer_artifact(
        _resolved(count=2), scan_payload=COMPACT_QR, issued_at=issued
    )
    expected = {key: claims[key] for key in LEASE_BINDING_KEYS}
    validate_artifact(artifact, expected=expected, now=issued - timedelta(seconds=30))
    with pytest.raises(OperationLeaseError) as refused:
        validate_artifact(artifact, expected=expected, now=issued - timedelta(seconds=31))
    assert refused.value.code == "OPERATION_LEASE_NOT_YET_VALID"

    # The PC reads one second before the server's issue time at the scan.
    app = _app(tmp_path, _LeaseServer(issued_at=issued))
    try:
        _scan_label(app)
        assert app.current_tray.operation_lease_id == LEASE_ID
    finally:
        app._ui_lane.close_idle()


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_seal_completed_time_is_not_before_lease_issued_when_pc_clock_is_behind(tmp_path):
    issued = FIXED_LEASE_NOW + timedelta(seconds=5)
    client = _LeaseServer(issued_at=issued)
    app = _app(tmp_path, client)
    try:
        _scan_label(app)
        namespace = app.transfer_seal_coordinator
        coordinator = TransferSealCoordinator(
            TransferSealStore(namespace.store.db_path),
            client,
            namespace.operation_lease_manager,
            owner_thread_id_provider=threading.get_ident,
        )
        coordinator.prepare(
            master_label=COMPACT_QR,
            master_label_fields=app._parse_new_format_qr(COMPACT_QR),
            item_id=ITEM,
            operator="tester",
            scanned_barcodes=[f"{ITEM}-SERIAL-001", f"{ITEM}-SERIAL-002"],
            operation_lease_id=LEASE_ID,
        )
        completion = namespace.operation_lease_manager.store.completion(LEASE_ID)
        # PC time is 5 s before issue; a server allowing none would refuse it.
        assert completion["operation_completed_at"] == utc_text(issued)
    finally:
        app._ui_lane.close_idle()


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_transition_not_yet_valid_retries_same_key_before_local(tmp_path):
    client = _LeaseServer(issued_at=FIXED_LEASE_NOW + timedelta(seconds=40))
    app = _app(tmp_path, client)
    app.legacy_label_transition = True
    local_starts = []
    release_requests = []
    app._start_transition_tray_after_preflight_failure = (
        lambda _barcode, _fields, _item, failure: local_starts.append(failure.code)
    )
    app._request_operation_lease_release = release_requests.append
    try:
        app._process_barcode_logic(COMPACT_QR)
        _pump_until(
            app.root,
            lambda: any(job[1] == REQUERY_MS for job in app.root.jobs) or bool(local_starts),
        )
        assert local_starts == []
        assert len(client.identities) == 1

        _pump_until(app.root, lambda: bool(local_starts))
        keys = [identity["idempotency_key"] for identity in client.identities]
        assert len(keys) == 2 and keys[0] == keys[1]
        assert local_starts == ["OPERATION_LEASE_NOT_YET_VALID"]
        # The lease the server issued meanwhile is given back.
        assert release_requests == [LEASE_ID]
    finally:
        app._ui_lane.close_idle()


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_reset_releases_the_prefetched_lease(tmp_path, monkeypatch):
    client = _LeaseServer()
    app = _app(tmp_path, client)
    try:
        _scan_label(app)
        token = client.artifacts[client.identities[0]["idempotency_key"]]["token"]
        client.up = False
        _reset(app, monkeypatch)
        _pump_until(app.root, lambda: bool(client.releases))
        _settle(app)
        assert app._operation_lease_releases_waiting == 1
        assert _attempt_status(app) == "PREFETCHED"

        client.up = True
        _pump_until(app.root, lambda: len(client.releases) == 2)
        _settle(app)
        first, retry = client.releases
        assert first == retry  # same key, byte-identical body
        assert first == {
            "authority_scope_id": "PLANT-01",
            "operation": "SEAL_TRANSFER_BUNDLE",
            "token": token,
            "reason": "LOCAL_RESET",
            "idempotency_key": first["idempotency_key"],
        }
        assert first["idempotency_key"].startswith("container-operation-lease-release:")
        assert client.lease_status == "RELEASED"
        assert _attempt_status(app) == "RELEASED"
        assert app._operation_lease_releases_waiting == 0
    finally:
        app._ui_lane.close_idle()


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_reset_with_pending_seal_intent_does_not_release_the_lease(tmp_path, monkeypatch):
    client = _LeaseServer()
    app = _app(tmp_path, client)
    try:
        _scan_label(app)
        # A completion made with this lease is stored (not yet sent).
        store = TransferSealStore(app.transfer_seal_coordinator.store.db_path)
        store.bind_owner_thread_id_provider(threading.get_ident)
        store.prepare(
            master_label=COMPACT_QR,
            source_identity={"source_bundle_id": "PHS-COMPACT-001", "item_id": ITEM},
            item_id=ITEM,
            operator="tester",
            scanned_barcodes=[f"{ITEM}-SERIAL-001", f"{ITEM}-SERIAL-002"],
            operation_lease_id=LEASE_ID,
        )
        _reset(app, monkeypatch)
        _settle(app)
        _pump_until(app.root, lambda: not app._requested_operation_lease_releases)
        _settle(app)
        assert client.releases == []
        assert client.lease_status == "ACTIVE"
        assert _attempt_status(app) == "PREFETCHED"
    finally:
        app._ui_lane.close_idle()


@pytest.mark.usefixtures("fixed_operation_lease_clock")
def test_reset_then_same_label_on_this_pc_keeps_its_reissued_lease(tmp_path, monkeypatch):
    client = _LeaseServer()
    app = _app(tmp_path, client)
    try:
        _scan_label(app)
        client.up = False
        _reset(app, monkeypatch)
        _pump_until(app.root, lambda: bool(client.releases))
        _settle(app)
        assert app._operation_lease_releases_waiting == 1

        # The server is back; the same PC scans the same label again and the
        # server replays the same lease for the same issue key.
        client.up = True
        _scan_label(app)
        keys = [identity["idempotency_key"] for identity in client.identities]
        assert keys[0] == keys[1]
        assert app.current_tray.operation_lease_id == LEASE_ID

        # The background retry that follows must not give it back.
        _pump_until(app.root, lambda: not _background_jobs(app.root))
        _settle(app)
        assert len(client.releases) == 1
        assert client.lease_status == "ACTIVE"  # this tray's completion is accepted
        assert _attempt_status(app) == "PREFETCHED"
        assert app._operation_lease_releases_waiting == 0
    finally:
        app._ui_lane.close_idle()

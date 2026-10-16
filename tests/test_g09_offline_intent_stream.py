"""Headless review regression, integrated into the checkout's tests directory.

Run only with the lane's approved headless/net-blocked runner and --tb=no.
The fixtures verify that all data roots stay inside pytest's temporary root.
No product or fixture values are printed.
"""
from pathlib import Path
import importlib
import sys
import csv
import pytest
from tests.operation_lease_fixtures import fixed_operation_lease_clock
from test_direct_sync_push import legacy_relay_without_runtime_lease

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock", "owned_tk_workers")


def _isolated_tests_directory():
    tests = Path(__file__).resolve().parent
    if tests.name != "tests" or not (tests.parent / "Container_Audit.py").is_file():
        pytest.skip("This regression requires the checkout tests directory")
    root = tests.parent
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(tests))
    return tests


def test_offline_queue_intent_is_audited_outside_forwarded_csv(tmp_path, monkeypatch):
    _isolated_tests_directory()
    helpers = importlib.import_module("test_phs2_master_preflight")
    app, _client = helpers._offline_queue_app(tmp_path, monkeypatch)
    app._process_barcode_logic(helpers.OTHER_LABEL)
    helpers._pump_until(
        app.root,
        lambda: not getattr(app, "_preflight_hold_switch_pending", False),
    )
    one_original = len(app._quarantined_preflight_holds()) == 1
    assert one_original, "Offline queue must retain exactly one original"
    forwarded_root = Path(app.save_folder).resolve()
    local_root = Path(app.local_events_folder).resolve()
    sandbox_root = tmp_path.resolve()
    roots_are_isolated = all(
        folder.is_relative_to(sandbox_root)
        for folder in (forwarded_root, local_root)
    )
    assert roots_are_isolated, "Review fixture escaped the isolated data root"
    intent_audited = False
    intent_forwarded = False
    for folder in {forwarded_root, local_root}:
        for path in folder.glob("*.csv"):
            with path.open(encoding="utf-8-sig", newline="") as stream:
                for row in csv.DictReader(stream):
                    is_intent = row.get("event") == "PHS2_PREFLIGHT_HOLD_OFFLINE_QUEUEING"
                    intent_audited = intent_audited or is_intent
                    intent_forwarded = intent_forwarded or (
                        is_intent and path.parent.resolve() == forwarded_root
                    )
    assert intent_audited, "The original queue intent must remain durably audited"
    assert not intent_forwarded, "An uncatalogued local audit intent entered the direct-sync CSV"


@pytest.mark.usefixtures("legacy_relay_without_runtime_lease")
def test_local_diagnostics_leave_catalogued_business_csv_acknowledgeable(tmp_path, monkeypatch):
    _isolated_tests_directory()
    helpers = importlib.import_module("test_phs2_master_preflight")
    relay = importlib.import_module("test_direct_sync_push")
    app = helpers._app(tmp_path, helpers.BlockingClient(helpers._resolved(count=2)))
    app.local_events_folder = str(tmp_path / "local_events")
    app.log_file_path = str(tmp_path / "이적작업이벤트로그_fixture_20260621.csv")
    assert all(Path(p).resolve().is_relative_to(tmp_path.resolve())
               for p in (app.save_folder, app.local_events_folder, app.log_file_path))
    app._trigger_session_direct_sync = lambda *_a, **_k: None
    diagnostics = {"PHS2_PREFLIGHT_HOLD_OFFLINE_QUEUEING", "APP_STOP_DEFERRED", "UI_LANE_FAULT", "APP_CLOSE_DELAY"}
    for event in sorted(diagnostics):
        assert helpers.ContainerAudit._log_event(app, event, detail={}, synchronous=True)
    assert helpers.ContainerAudit._log_event(
        app, "SCAN_OK", detail={"product_barcode": "synthetic-product"}, synchronous=True)
    forwarded = Path(app.log_file_path)
    with forwarded.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["event"] for row in rows] == ["SCAN_OK"]
    local_rows = []
    for path in Path(app.local_events_folder).glob("*.csv"):
        with path.open(encoding="utf-8-sig", newline="") as stream:
            local_rows.extend(csv.DictReader(stream))
    assert {row["event"] for row in local_rows} == diagnostics
    assert len(local_rows) == len(diagnostics)
    manifest, manifest_path = relay.make_manifest(tmp_path)
    credentials = relay.make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    entry = relay.enqueue_source_file_for_relay(
        db_path=db_path, spool_dir=tmp_path / "spool", source_file_path=forwarded,
        producer_manifest_path=manifest_path, credentials=credentials)
    receipt = {
        "request_id": "synthetic-local-audit-routing", "upload_id": "synthetic-local-audit-routing",
        "client_batch_id": entry.relay_id,
        "server_source_file_id": f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{entry.relative_path}",
        "committed": True, "status": "accepted", "projection_disposition": "COMPLETE",
        "retryable": False, "next_retry_after": None,
        "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
    }
    # Exercise the existing client receipt/ACK helper with a synthetic response;
    # no live server or authentication policy is changed by this test.
    result = relay.drain_one_relay_batch(
        db_path=db_path, credentials=credentials,
        session=relay.FakeSession(relay.FakeResponse(200, receipt)), status_dir=tmp_path / "status")
    assert result is not None and result.success is True
    assert relay.relay_queue_status(db_path)["counts"][relay.RELAY_STATUS_ACKED] == 1

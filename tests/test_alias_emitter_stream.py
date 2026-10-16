"""Actual alias audit writer and relay source/receipt boundary (no network)."""
import csv
import importlib
import io
import json
from pathlib import Path
import uuid

import pytest
from tests.operation_lease_fixtures import fixed_operation_lease_clock
from test_direct_sync_push import legacy_relay_without_runtime_lease

pytestmark = pytest.mark.usefixtures(
    "fixed_operation_lease_clock", "owned_tk_workers", "legacy_relay_without_runtime_lease"
)


def test_waiting_marker_failure_stays_local_through_relay_receipt(tmp_path, monkeypatch):
    helpers = importlib.import_module("test_phs2_master_preflight")
    relay = importlib.import_module("test_direct_sync_push")
    from tools.direct_sync_relay_runner import _scan_source_files

    app = helpers._app(tmp_path, helpers.BlockingClient(helpers._resolved(count=2)))
    app.local_events_folder = str(tmp_path / "local_events")
    app.log_file_path = str(tmp_path / "이적작업이벤트로그_fixture_20260621.csv")
    app._trigger_session_direct_sync = lambda *_a, **_k: None
    app._log_event = lambda *a, **k: helpers.ContainerAudit._log_event(app, *a, **k)
    app._log_phs_replacement_waiting_failure(
        context=None, pair=("synthetic-old-label", "synthetic-new-label"), error=OSError()
    )
    assert app._log_event("SCAN_OK", detail={"product_barcode": "synthetic-product"}, synchronous=True)
    selected = _scan_source_files(str(tmp_path), ["*.csv"], 10, min_age_seconds=0)
    assert selected == [Path(app.log_file_path)]
    assert all(p.resolve().is_relative_to(tmp_path.resolve()) for p in selected)
    with selected[0].open(encoding="utf-8-sig", newline="") as stream:
        business_rows = list(csv.DictReader(stream))
    manifest, manifest_path = relay.make_manifest(tmp_path)
    credentials = relay.make_credentials()
    db = tmp_path / "relay.sqlite3"
    entry = relay.enqueue_source_file_for_relay(
        db_path=db, spool_dir=tmp_path / "spool", source_file_path=selected[0],
        producer_manifest_path=manifest_path, credentials=credentials,
    )
    catalog = json.loads((Path(__file__).parents[1] / "kmtech_factory_contracts/bundle/v1/catalogs/canonical-stream-catalog.json").read_text())
    accepted = next(s["raw_event_names"] for s in catalog["streams"] if s["app_id"] == "container_audit")

    class CatalogReceipt:
        def __init__(self):
            self.unknown = []
            self.quarantined = None

        def post(self, _url, *, data, files, **_kwargs):
            rows = list(csv.DictReader(io.StringIO(files["file"][1].read().decode("utf-8-sig"))))
            self.unknown = [r["event"] for r in rows if r["event"] not in accepted]
            self.quarantined = len(self.unknown)
            return relay.FakeResponse(200, {
                "request_id": "synthetic-alias", "upload_id": "synthetic-alias",
                "client_batch_id": entry.relay_id,
                "server_source_file_id": f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{entry.relative_path}",
                "committed": True, "status": "accepted", "retryable": False,
                "next_retry_after": None,
                "projection_disposition": "QUARANTINED" if self.unknown else "COMPLETE",
                "totals": {"inserted": len(rows) - len(self.unknown), "replayed": 0,
                           "quarantined": len(self.unknown), "errors": 0},
                "issues": [{"code": "UNKNOWN_EVENT_TYPE", "event_type": e} for e in self.unknown],
            })

    session = CatalogReceipt()
    result = relay.drain_one_relay_batch(db_path=db, credentials=credentials, session=session, status_dir=tmp_path / "status")
    assert not session.unknown, f"UNKNOWN_EVENT_TYPE: {session.unknown}; quarantined={session.quarantined}; success={result.success}"
    assert session.quarantined == 0
    assert result.success is True
    assert relay.relay_queue_status(db)["counts"][relay.RELAY_STATUS_ACKED] == 1
    assert [row["event"] for row in business_rows] == ["SCAN_OK"]
    local = []
    for path in Path(app.local_events_folder).glob("*.csv"):
        with path.open(encoding="utf-8-sig", newline="") as stream:
            local.extend(csv.DictReader(stream))
    assert [r["event"] for r in local] == ["PHS_REPLACEMENT_WAITING_MARK_FAILED"]
    assert json.loads(local[0]["details"])["exception_type"] == "OSError"


@pytest.mark.parametrize("event", [
    "WORKER_ACTION_AUTHORIZED", "WORKER_ACTION_RESUMED", "WORKER_ACTION_APPLIED",
])
def test_worker_lifecycle_audit_remains_readable_outside_business_csv(tmp_path, event):
    helpers = importlib.import_module("test_phs2_master_preflight")
    from tools.direct_sync_relay_runner import _scan_source_files

    app = helpers._app(tmp_path, helpers.BlockingClient(helpers._resolved(count=2)))
    app.local_events_folder = str(tmp_path / "local_events")
    app.log_file_path = str(tmp_path / "이적작업이벤트로그_fixture_20260621.csv")
    app._trigger_session_direct_sync = lambda *_a, **_k: None
    app._log_event = lambda *a, **k: helpers.ContainerAudit._log_event(app, *a, **k)
    intent = {"operation_key": str(uuid.uuid4()), "action": "CA.TRAY_HOLD",
              "target": {"id": "synthetic-target"},
              "operator": {"local_id": "synthetic-operator", "login_epoch": "synthetic-epoch"}}
    assert app._admin_pin_audit(event, intent)
    assert app._admin_pin_effect_audited(event, intent["operation_key"])
    assert _scan_source_files(str(tmp_path), ["*.csv"], 10, min_age_seconds=0) == []
    assert not Path(app.log_file_path).exists()
    local = list(Path(app.local_events_folder).glob("*.csv"))
    assert len(local) == 1
    with local[0].open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["event"] for row in rows] == [event]

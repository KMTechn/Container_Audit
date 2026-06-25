from pathlib import Path


REPORT = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "COMPANY_SERVER_READONLY_PRECHECK_20260625.md"
)


def _report_text() -> str:
    return REPORT.read_text(encoding="utf-8")


def test_company_server_precheck_records_readonly_side_effect_boundary():
    text = _report_text()

    required = [
        "read-only evidence only",
        "No POST upload executed",
        "no producer credential used",
        "no production DB mutation",
        "no scheduled task/service change",
        "no Syncthing config change",
        "Secret-bearing local config values",
    ]

    assert [item for item in required if item not in text] == []


def test_company_server_precheck_records_registered_syncthing_server_and_folder_scope():
    text = _report_text()

    required = [
        "Syncthing device named `Server` is registered and connected",
        "`175.45.200.171:22000`",
        "`C:\\Sync` is not registered in Syncthing config",
        "only shared folder observed in the Syncthing config is `C:\\Obsidian`",
        "`SyncthingStartup`",
        "does not prove `Container_Audit` data is currently synced",
    ]

    assert [item for item in required if item not in text] == []


def test_company_server_precheck_distinguishes_https_from_http_ingest_route():
    text = _report_text()

    required = [
        "`https://175.45.200.171/api/producer-ingest/v1/source-file`",
        "IP-based HTTPS remains unapproved for worker PCs",
        "TLS certificate trust failure",
        "Use the FQDN route for future approved testing",
        "`https://worker.kmtecherp.com/api/producer-ingest/v1/source-file`",
        "FQDN HTTPS `OPTIONS` returned 200 with `Allow: OPTIONS, POST`",
        "no POST upload, HMAC, nonce, idempotency, receipt, or DB write was tested",
        "`http://175.45.200.171:8089/health`",
        "Returned 200 from WorkerAnalysisGUI-web health",
        "`http://175.45.200.171:8089/api/producer-ingest/v1/source-file`",
        "Route exists with `POST, OPTIONS`",
        "Internal HTTP route exists; external cutover validation must use trusted HTTPS FQDN",
    ]

    assert [item for item in required if item not in text] == []


def test_company_server_precheck_records_ingest_health_blocker():
    text = _report_text()

    required = [
        "Returned 503",
        "Latest read-only recheck confirmed Syncthing `Server` connected",
        "FQDN HTTPS producer route `OPTIONS` returned 200",
        "`reason=PLAN_C_ROLLOUT_GATE_BLOCKED`",
        "`common_projection_schema=healthy`",
        "`schema_ready=true`",
        "`rollout_gates.status=blocked_pending_promotion_evidence`",
        "`blocking_reasons=[\"missing_promotion_evidence_bundle\"]`",
        "`rollback_marker_and_drain_receipt`",
        "direct-sync schema/ops status is ready",
    ]

    assert [item for item in required if item not in text] == []


def test_company_server_precheck_records_local_received_data_and_upload_blockers():
    text = _report_text()

    required = [
        "`17` CSV files and `102` total rows",
        "No rows dated `2026-06-25`",
        "no completed `TRAY_COMPLETE` sessions",
        "completed-session count is `0`",
        "`2` completed sessions on `2026-06-23`, total `120` pieces",
        "Do not POST production or staging upload data to the producer endpoint yet",
        "Approved staging/test HTTPS URL",
        "current FQDN `OPTIONS` route exists but upload is not approved",
        "Per-PC `source_host_id`, `producer_install_id`, key id",
    ]

    assert [item for item in required if item not in text] == []

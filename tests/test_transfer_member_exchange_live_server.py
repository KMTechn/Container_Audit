from __future__ import annotations

from pathlib import Path
import sys
from urllib.parse import urlsplit

import pytest


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
WEB_ROOT = WORKSPACE_ROOT / "WorkerAnalysisGUI-web"
if not WEB_ROOT.is_dir():
    pytest.skip(
        "cross-repository WorkerAnalysisGUI-web checkout is unavailable",
        allow_module_level=True,
    )

sys.path.insert(0, str(WEB_ROOT))
sys.path.insert(0, str(WEB_ROOT / "tests"))

from test_logistics_api_v1 import SCOPE, TOKEN, _app, _headers  # noqa: E402
from test_logistics_p3_transfer_package import _complete_phs  # noqa: E402
from transfer_member_exchange import (  # noqa: E402
    TransferMemberExchangeCoordinator,
    TransferMemberExchangeStore,
)
from transfer_seal import LogisticsTransferClient  # noqa: E402


class _FlaskResponse:
    def __init__(self, response):
        self.status_code = response.status_code
        self._response = response

    def json(self):
        return self._response.get_json()


class _FlaskSession:
    def __init__(self, client):
        self.client = client

    def request(self, method, url, **kwargs):
        parsed = urlsplit(url)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        return _FlaskResponse(
            self.client.open(
                path,
                method=method,
                headers=kwargs.get("headers"),
                json=kwargs.get("json"),
            )
        )


def test_container_exchange_traverses_live_capability_resolver_and_commit(tmp_path):
    app, _db_path = _app(tmp_path / "server", opening_qty=3)
    web = app.test_client()
    target_id, _target_version, target_members = _complete_phs(
        web,
        session_id="LIVE-CONTAINER-TARGET",
        count=2,
        label="LIVE-CONTAINER-TARGET",
        start_index=0,
    )
    source_id, _source_version, source_members = _complete_phs(
        web,
        session_id="LIVE-CONTAINER-SOURCE",
        count=1,
        label="LIVE-CONTAINER-SOURCE",
        start_index=10,
    )
    target = web.get(
        f"/logistics/api/v1/bundles/{SCOPE}/{target_id}", headers=_headers()
    ).get_json()["data"]
    source = web.get(
        f"/logistics/api/v1/bundles/{SCOPE}/{source_id}", headers=_headers()
    ).get_json()["data"]
    old_barcode = next(
        row["normalized_barcode"]
        for row in target["members"]
        if row["unit_id"] == target_members[0]
    )
    new_barcode = next(
        row["normalized_barcode"]
        for row in source["members"]
        if row["unit_id"] == source_members[0]
    )
    client = LogisticsTransferClient(
        "https://logistics.test.invalid",
        TOKEN,
        "container-live-host",
        device_id="container-live-device",
        session=_FlaskSession(web),
    )
    coordinator = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(tmp_path / "desktop" / "exchange.sqlite3"),
        client,
    )
    prepared = coordinator.prepare(
        master_label=f"BND={target_id}",
        master_label_fields={
            "BND": target_id,
            "AUTH_SCOPE": SCOPE,
            "CLC": "ITEM-API",
        },
        item_id="ITEM-API",
        operator="live-contract-test",
        old_barcodes=[old_barcode],
        new_barcodes=[new_barcode],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED", result
    assert result.target_label_action == "RETAIN_IDENTITY_LABEL"
    assert result.target_label_identity_remains_valid is True
    assert result.target_label_membership_bound is False

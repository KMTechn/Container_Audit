"""Optional in-process check against the pinned Web admin-pin.v1 server snapshot."""

import importlib.util
import os
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import container_admin_pin as pin


def test_pinned_web_383e6c4_issues_and_consumes_ca_proof(monkeypatch, tmp_path):
    root_text = os.environ.get("CA_PIN_WEB_SNAPSHOT_ROOT", "")
    if not root_text:
        pytest.skip("pinned Web source archive is supplied only for the PIN integration gate")
    if os.environ.get("CA_PIN_WEB_CHILD") != "1":
        result = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
             f"{__file__}::test_pinned_web_383e6c4_issues_and_consumes_ca_proof",
             "--basetemp", str(tmp_path / "child")],
            env={**os.environ, "CA_PIN_WEB_CHILD": "1"},
            capture_output=True, text=True, timeout=90, check=False,
        )
        assert result.returncode == 0, (result.stdout + result.stderr)[-4000:]
        return
    root = Path(root_text)
    assert (root / "admin_pin.py").is_file()
    sys.path.insert(0, str(root))
    try:
        specification = importlib.util.spec_from_file_location(
            "_pinned_web_admin_pin_test", root / "tests" / "test_admin_pin.py")
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        app, principal = module._http_app(monkeypatch, tmp_path)
        app.extensions["admin_pin_store"].set_pin(principal["principal_id"], "582714")
        web_client = app.test_client()

        def transport(path, body, headers):
            response = web_client.post(
                path, data=body, headers=headers, base_url="https://localhost")
            return response.status_code, response.data

        monkeypatch.setattr(pin, "load_credentials_from_json", lambda _path: SimpleNamespace(
            endpoint_url="https://localhost/api/producer-ingest/v1",
            producer_id="test-producer", key_id="test-key",
            secret="machine-secret-A8r9P2", tls_ca_bundle_path="",
        ))
        client = pin.AdminPinClient("pinned-web-fixture", transport=transport)
        target = {"kind": "pair", "id": "PAIR-1", "state_fingerprint": "a" * 64}
        operator = {"local_id": "worker-1", "login_epoch": uuid.uuid4().hex}
        issued = client.verify(
            request_id=str(uuid.uuid4()), admin_id="A1", pin="582714",
            action="CA.PAIR_RETRY", target=target, operator=operator,
        )
        operation_key = str(uuid.uuid4())
        client.redeem(
            verification_id=issued["verification_id"], proof=issued["proof"],
            operation_key=operation_key, action="CA.PAIR_RETRY",
            target=target, operator=operator,
        )
        assert client.status(issued["verification_id"], operation_key) == "CONSUMED"
    finally:
        sys.path.remove(str(root))

"""Optional in-process check against the pinned Web admin-pin.v1 server snapshot."""

import importlib.util
import os
import sqlite3
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import container_admin_pin as pin


@pytest.mark.parametrize("scenario", ["allowed", "ca_allowed", "wrong_pin", "admin_locked", "root_revoked", "role_absent", "locked_root_revoked"])
def test_pinned_web_ca_authorization_has_durable_boundaries(monkeypatch, tmp_path, scenario):
    root_text = os.environ.get("CA_PIN_WEB_SNAPSHOT_ROOT", "")
    if not root_text:
        pytest.skip("pinned Web source archive is supplied only for the PIN integration gate")
    if os.environ.get("CA_PIN_WEB_CHILD") != "1":
        result = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
             f"{__file__}::test_pinned_web_ca_authorization_has_durable_boundaries[{scenario}]",
             "--basetemp", str(tmp_path / "child")],
            env={**os.environ, "CA_PIN_WEB_CHILD": "1"},
            capture_output=True, text=True, timeout=90, check=False,
        )
        assert result.returncode == 0, (result.stdout + result.stderr)[-4000:]
        return
    root = Path(root_text)
    assert (root / "admin_pin.py").is_file()
    from tests.test_container_admin_pin import make_headless_app, SignedPinServer
    # Preserve native type introspection through the CA detector's SQL proxy.
    # Its execute/transaction hooks still observe every operation.
    guarded = sqlite3.connect(":memory:")
    proxy_type = type(guarded)
    guarded.close()
    if proxy_type.__module__ == "tests.conftest":
        class NativeTypeProxy(proxy_type):
            @property
            def __class__(self):
                return sqlite3.Connection

        guarded_connect = sqlite3.connect

        def compatible_connect(*args, **kwargs):
            connection = guarded_connect(*args, **kwargs)
            if type(connection) is proxy_type:
                object.__setattr__(connection, "__class__", NativeTypeProxy)
            return connection

        monkeypatch.setattr(sqlite3, "connect", compatible_connect)
    from werkzeug.routing import Map
    # A guarded Python factory needs the same static binding as the native lock factory.
    monkeypatch.setattr(Map, "lock_class", staticmethod(threading.Lock))
    # Each app owns a different module with this name in the isolated integration child.
    def app_specific_module(name):
        return name == "worker_roster" or name == "kmtech_factory_contracts" or name.startswith("kmtech_factory_contracts.")

    ca_modules = {name: module for name, module in sys.modules.items() if app_specific_module(name)}

    def restore_ca_modules():
        for name in tuple(sys.modules):
            if app_specific_module(name):
                sys.modules.pop(name, None)
        sys.modules.update(ca_modules)

    for name in ca_modules:
        sys.modules.pop(name, None)
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
        store = app.extensions["admin_pin_store"]
        arguments = {"admin_id": "A1", "pin": "582714", "action": "CA.PAIR_RETRY",
                     "target": target, "operator": operator}
        if scenario == "allowed":
            issued = client.verify(request_id=str(uuid.uuid4()), **arguments)
            operation_key = str(uuid.uuid4())
            client.redeem(
                verification_id=issued["verification_id"], proof=issued["proof"],
                operation_key=operation_key, action="CA.PAIR_RETRY", target=target, operator=operator,
            )
            assert client.status(issued["verification_id"], operation_key) == "CONSUMED"
            with store.connect() as conn:
                assert conn.execute("SELECT status,operation_key FROM admin_pin_grants").fetchone()[:] == ("CONSUMED", operation_key)
            return

        prior = None
        if scenario in {"root_revoked", "role_absent", "locked_root_revoked"}:
            prior = client.verify(request_id=str(uuid.uuid4()), **arguments)
        if scenario in {"admin_locked", "locked_root_revoked"}:
            # Fifteen signed failures across three devices reach the ADMIN limit;
            # a fresh device below has no ADMIN_DEVICE lock of its own.
            for device in ("isolated-hostile-1", "isolated-hostile-2", "isolated-hostile-3"):
                monkeypatch.setenv("PRODUCER_INGEST_TEST_INSTALL_ID", device)
                for _ in range(5):
                    with pytest.raises(pin.AdminPinError) as rejected:
                        client.verify(request_id=str(uuid.uuid4()), **dict(arguments, pin="000000"))
                    assert rejected.value.code == "PIN_INVALID" and not rejected.value.unknown
            monkeypatch.setenv("PRODUCER_INGEST_TEST_INSTALL_ID", "isolated-clean-device")
            with store.connect() as conn:
                lock = conn.execute("SELECT failures,locked_until FROM admin_pin_limits WHERE scope='ADMIN' AND identity='A1'").fetchone()
                assert lock[0] == 15 and lock[1] > 0
        if scenario in {"root_revoked", "locked_root_revoked"}:
            store.disable_admin("A1", actor_id="isolated-root", reason="isolated root revocation", reason_code="ROOT_REVOKED")
            with store.connect() as conn:
                assert conn.execute("SELECT status FROM desktop_admin_links WHERE admin_id='A1'").fetchone()[0] == "DISABLED"
        if scenario == "role_absent":
            from auth_identity import AuthIdentityStore
            AuthIdentityStore(app.config["WORKER_ANALYSIS_DB_PATH"]).provision_role(
                principal["principal_id"], "desktop_admin", assigned_by="isolated-root",
                reason="isolated role revocation", active=False)

        # Use the actual CA approval entry used by manager recovery handlers, and
        # inspect its durable local intent as well as the public HTTP server.
        sys.path.remove(str(root))
        restore_ca_modules()
        ca, _audits, _notices = make_headless_app(monkeypatch, tmp_path / "ca", SignedPinServer())
        ca._admin_pin_client = client
        ca._prompt_blocked_work_admin_pin = lambda **_request: ("A1", "000000" if scenario == "wrong_pin" else "582714")
        source = tmp_path / "original-recovery.json"
        source.write_bytes(b'{"version":1}\n')
        before = source.read_bytes()
        approval = ca._admin_pin_approval_for(
            "CA.PAIR_RETRY", "PAIR-1", lambda: {"bytes": source.read_text()},
            ("PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-PIN|CLC=AAA2270730100|LBL=PIN|HSH=0123456789abcdef",), lambda _intent: False)
        assert (approval is not None) == (scenario == "ca_allowed")
        assert source.read_bytes() == before
        intents = ca._admin_pin_store().pending("CA.PAIR_RETRY", "PAIR-1", include_applied=True)
        # Rejected intents remain on disk but are excluded from pending selection.
        persisted = list(ca._admin_pin_store().directory.glob("*.json"))
        assert len(persisted) == 1
        import json
        intent = json.loads(persisted[0].read_text())
        if scenario == "ca_allowed":
            assert intent["state"] == "CONSUMED" and len(intents) == 1
            with store.connect() as conn:
                assert conn.execute("SELECT status FROM admin_pin_grants").fetchone()[0] == "CONSUMED"
            return
        assert intent["state"] == "REJECTED" and intent["reason"] == "PIN_INVALID" and not intents
        if scenario in {"admin_locked", "locked_root_revoked"}:
            with store.connect() as conn:
                assert conn.execute("SELECT outcome,reason_code FROM admin_pin_audit WHERE event_type='VERIFY' ORDER BY rowid DESC LIMIT 1").fetchone()[:] == ("LOCKED", "PIN_LOCKED")
        assert "582714" not in persisted[0].read_text() and "000000" not in persisted[0].read_text()
        if prior is not None:
            monkeypatch.setenv("PRODUCER_INGEST_TEST_INSTALL_ID", "test-install")
            with pytest.raises(pin.AdminPinError) as rejected:
                client.redeem(verification_id=prior["verification_id"], proof=prior["proof"],
                              operation_key=str(uuid.uuid4()), action="CA.PAIR_RETRY",
                              target=target, operator=operator)
            assert rejected.value.code == "PROOF_EXPIRED" and not rejected.value.unknown
        with store.connect() as conn:
            statuses = [r[0] for r in conn.execute("SELECT status FROM admin_pin_grants")]
            assert statuses == (["REVOKED"] if prior is not None else [])
    finally:
        if str(root) in sys.path:
            sys.path.remove(str(root))
        restore_ca_modules()

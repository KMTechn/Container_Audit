"""Offline Cloudflare-shaped responses at the existing client boundaries."""

import gzip
import io
import socket
from types import SimpleNamespace

import pytest
import requests
from urllib3.response import HTTPResponse

import Container_Audit as app
import container_admin_pin as pin
import direct_sync_push as push
import item_catalog_sync as catalog
import producer_runtime_client as runtime
from tests.test_container_admin_pin import make_client, pin_inputs, SignedPinServer
from tests.test_direct_sync_push import make_credentials, make_manifest, write_csv
from tests.test_feed_packet_prefix import _stock_feed
from tests.test_item_catalog_sync import CATALOG, _profile
from transfer_client import LogisticsTransferClient
from transfer_common import TransferSealError


USER_AGENT = "KMTech-ContainerAudit/1.0"


@pytest.fixture(autouse=True)
def _offline_network(monkeypatch):
    def no_connection(*_args, **_kwargs):
        raise AssertionError("offline HTTP regression attempted a socket connection")
    monkeypatch.setattr(socket, "getaddrinfo", lambda _host, port, **_kwargs:
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))])
    monkeypatch.setattr(socket.socket, "connect", no_connection)
    monkeypatch.setattr(socket.socket, "connect_ex", no_connection)
    monkeypatch.setattr(socket, "create_connection", no_connection)


def response(status, payload, *, compressed=False):
    result = requests.Response()
    result.status_code = status
    result.url = "https://server.example.test/"
    if compressed:
        result.headers["Content-Encoding"] = "gzip"
        result.raw = HTTPResponse(body=io.BytesIO(gzip.compress(payload)),
                                  headers=result.headers, preload_content=False)
    else:
        result._content = payload
    return result


@pytest.mark.parametrize("route", ["verifications", "roster"])
def test_pin_and_roster_send_product_user_agent(monkeypatch, route):
    seen = []
    def transport(path, body, headers):
        seen.append(headers["User-Agent"])
        return (201 if route == "verifications" else 200), b'{"ok":true}'
    client = make_client(monkeypatch, transport)
    if route == "roster":
        client.query_roster(authority_scope_id="scope", known_version=None)
    else:
        client.post(route, {})
    assert seen == [USER_AGENT]


@pytest.mark.parametrize("status", [403, 500, 502, 503])
def test_pin_html_error_shows_http_code_without_claiming_result(monkeypatch, status):
    client = make_client(monkeypatch, lambda *_: (status, b'<html>error code: 1010</html>'))
    with pytest.raises(pin.AdminPinError) as caught:
        client.post("verifications", {})
    assert caught.value.code == f"HTTP_{status}"
    assert caught.value.unknown is True
    message = pin.operator_message(caught.value.code)
    assert "회사 서버" in message and f"코드 {status}" in message
    assert ("거절" if status == 403 else "오류") in message


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("status", [403, 500, 502, 503])
def test_logistics_html_error_retains_unknown_commit(method, status):
    client = LogisticsTransferClient("https://server.example.test", "fixture", "fixture-host",
        session=SimpleNamespace(request=lambda *_args, **_kwargs:
            response(status, b'<html>error code: 1010</html>')))
    with pytest.raises(TransferSealError) as caught:
        client._request(method, "/api/logistics/v1/fixture", idempotency_key="same-key")
    error = caught.value
    assert error.code == ("LOGISTICS_SERVER_REJECTED" if status == 403 else "LOGISTICS_SERVER_ERROR")
    assert error.status_code == status and error.committed is None and error.retryable is True
    assert "회사 서버" in str(error) and f"코드 {status}" in str(error)
    assert client.last_successful_transmission_at == ""


def test_logistics_gzip_json_and_request_headers():
    seen = []
    def request(method, url, **kwargs):
        seen.append(kwargs)
        return response(200, b'{"ok":true,"data":{"members":["fixture"]}}', compressed=True)
    client = LogisticsTransferClient("https://server.example.test", "fixture", "fixture-host",
                                     session=SimpleNamespace(request=request))
    assert client._request("GET", "/fixture", idempotency_key="same-key") == {"members": ["fixture"]}
    assert seen[0]["headers"]["User-Agent"] == USER_AGENT
    assert seen[0]["headers"]["Idempotency-Key"] == "same-key"
    assert seen[0]["allow_redirects"] is False and seen[0]["timeout"] == 10


def test_pin_gzip_signed_json_contract(monkeypatch):
    server = SignedPinServer()
    client = make_client(monkeypatch, server)
    def post(url, **kwargs):
        status, body = server("/api/admin-pin/v1/verifications", kwargs["data"], kwargs["headers"])
        assert kwargs["headers"]["User-Agent"] == USER_AGENT
        return response(status, body, compressed=True)
    client.transport = None
    client.session = SimpleNamespace(post=post)
    assert client.verify(**pin_inputs())["verification_id"] == server.verification_id


def test_catalog_gzip_csv_and_product_user_agent(monkeypatch, tmp_path):
    monkeypatch.setattr(catalog, "_load_item_catalog_logistics_profile", lambda _path: _profile())
    bundled, cache = tmp_path / "bundle.csv", tmp_path / "cache.csv"
    bundled.write_bytes(CATALOG)
    seen = []
    def get(url, **kwargs):
        seen.append(kwargs["headers"])
        return response(200, CATALOG, compressed=True)
    assert catalog.refresh_item_catalog(bundled, cache_path=cache, get=get) == cache
    assert cache.read_bytes() == CATALOG and seen[0]["User-Agent"] == USER_AGENT


@pytest.mark.parametrize("status", [403, 502, 503])
def test_catalog_startup_displays_http_reason(monkeypatch, tmp_path, status):
    monkeypatch.setattr(catalog, "_load_item_catalog_logistics_profile", lambda _path: _profile())
    bundle = tmp_path / "bundle.csv"
    bundle.write_bytes(CATALOG)
    with pytest.raises(catalog.ItemCatalogSyncError) as caught:
        catalog.refresh_item_catalog(bundle, cache_path=tmp_path / "cache.csv",
            get=lambda *_args, **_kwargs: response(status, b'<html>error code: 1010</html>'))
    assert caught.value.cause_code == catalog.REQUEST_FAILED_NO_CACHE
    seen = []
    monkeypatch.setattr(app, "_show_startup_notice", lambda title, message: seen.append(message))
    app._show_item_catalog_startup_error(caught.value.cause_code,
        http_status_code=caught.value.diagnostic_context["http_status_code"])
    assert "회사 서버" in seen[0] and f"코드 {status}" in seen[0]
    assert ("거절" if status == 403 else "오류") in seen[0]


def test_pin_gzip_limit_applies_after_decompression(monkeypatch):
    client = make_client(monkeypatch, None)
    client.session = SimpleNamespace(post=lambda *_args, **_kwargs:
        response(201, b'{"ok":true,"padding":"' + b'x' * 8192 + b'"}', compressed=True))
    with pytest.raises(pin.AdminPinError) as caught:
        client.post("verifications", {})
    assert caught.value.code == "VERIFY_UNAVAILABLE" and caught.value.unknown is True


def test_invalid_success_body_never_confirms_pin_or_logistics(monkeypatch):
    client = make_client(monkeypatch, lambda *_args: (201, b'<html>error code: 1010</html>'))
    with pytest.raises(pin.AdminPinError) as caught:
        client.post("verifications", {})
    assert caught.value.code == "VERIFY_UNAVAILABLE" and caught.value.unknown is True
    logistics = LogisticsTransferClient("https://server.example.test", "fixture", "fixture-host",
        session=SimpleNamespace(request=lambda *_args, **_kwargs: response(200, b'<html>not a receipt</html>')))
    with pytest.raises(TransferSealError) as caught:
        logistics._request("POST", "/fixture", idempotency_key="same-key")
    assert caught.value.code == "INVALID_SERVER_RESPONSE" and caught.value.committed is None
    assert logistics.last_successful_transmission_at == ""


def test_relay_upload_and_restore_share_product_user_agent(tmp_path):
    credentials = make_credentials()
    _, manifest = make_manifest(tmp_path)
    plan = push.build_source_file_plan(source_file_path=write_csv(tmp_path),
        producer_manifest_path=manifest, credentials=credentials)
    headers = push.signed_headers(credentials, plan.metadata)
    restore_url = push.build_raw_artifact_restore_url(credentials.endpoint_url,
        content_sha256=plan.content_sha256, byte_length=plan.byte_length)
    restore = push.restore_signed_headers(credentials, plan.metadata, restore_url)
    assert headers["User-Agent"] == restore["User-Agent"] == USER_AGENT


def test_runtime_lease_sends_product_user_agent():
    seen = []
    def post(url, **kwargs):
        seen.append(kwargs["headers"])
        return response(503, b'<html>unavailable</html>')
    _, error = runtime._post_lease_request(request_value={}, credentials=make_credentials(),
        session=SimpleNamespace(post=post), timeout=10)
    assert seen[0]["User-Agent"] == USER_AGENT
    assert error is not None and error.retryable is True


def test_registration_sends_product_user_agent(monkeypatch):
    from tools import register_container_audit_worker_pc as register
    seen = []
    class Session:
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def post(self, url, **kwargs):
            seen.append(kwargs)
            return response(403, b'<html>error code: 1010</html>')
    monkeypatch.setattr(register.requests, "Session", Session)
    register._post_enrollment_request("https://server.example.test/register", json={}, headers={},
                                     timeout=10, allow_redirects=False, verify=True)
    assert seen[0]["headers"]["User-Agent"] == USER_AGENT
    assert seen[0]["verify"] is True and seen[0]["allow_redirects"] is False


def test_private_update_requests_send_product_user_agent(monkeypatch):
    import logistics_runtime_profile
    monkeypatch.setattr(logistics_runtime_profile, "load_logistics_runtime_profile", lambda **_kwargs: None)
    assert app._private_update_request_kwargs("https://server.example.test/manifest")["headers"]["User-Agent"] == USER_AGENT


def test_feed_signature_and_packet_send_product_user_agent(monkeypatch, tmp_path):
    import auto_update
    _stock_feed(tmp_path, monkeypatch, "canonical")
    original = requests.Session.get
    seen = []
    def get(self, url, **kwargs):
        seen.append(kwargs["headers"]["User-Agent"])
        return original(self, url, **kwargs)
    monkeypatch.setattr(requests.Session, "get", get)
    assert auto_update.prepare_feed_packet(tmp_path)["status"] == "PREPARED"
    assert seen == [USER_AGENT] * 3

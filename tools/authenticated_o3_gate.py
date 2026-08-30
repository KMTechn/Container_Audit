#!/usr/bin/env python3
"""Secret-safe authenticated qualification for the three server5 origins.

The unauthenticated ``three_origin_gate.py`` remains the transport, TLS,
listener, and PID authority.  This companion consumes that gate's PASS
evidence and adds isolated login/cookie/logout, authenticated catalog, SQLite
quick-check, and negative authentication probes.

Credential material is accepted only as bounded JSON on standard input.  Raw
credentials, cookies, response bodies, and exception text are never emitted.
Running the live probe changes authentication session/audit/throttle state, so
it requires an explicit deployment-window acknowledgement.  It never writes a
business row, restarts a process, or changes server configuration.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import http.client
import importlib.util
import io
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence


SCHEMA = "kmtech.authenticated-o3-gate.v1"
POINTER_SCHEMA = "kmtech.authenticated-o3-pointer.v1"
BINDING_SCHEMA = "kmtech.authenticated-o3-binding.v1"
CREDENTIAL_SCHEMA = "kmtech.authenticated-o3-credentials.v1"
GATE = "server5-authenticated-three-origin"
HOST = "server5.autoloop.test"
SOURCE_COMMIT_HEADER = "X-KMTech-Source-Commit"
CATALOG_PATH = "/inbound/api/item-catalog.csv"
CATALOG_HEADER = ("Item Code", "Item Name", "Spec", "Tray Image")
CANONICAL_PORTS: dict[str, int] = {
    "inspection": 18455,
    "label": 18456,
    "container": 18457,
}
PROFILES = tuple(CANONICAL_PORTS)
ACKNOWLEDGEMENT = "AUTH_SESSION_AUDIT_WRITES_APPROVED"
SIDE_EFFECT_CLASS = "AUTH_SESSION_AUDIT_AND_THROTTLE_STATE"

MAX_BINDING_BYTES = 64 * 1024
MAX_CREDENTIAL_BYTES = 32 * 1024
MAX_TRANSPORT_EVIDENCE_BYTES = 512 * 1024
MAX_CA_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_COOKIE_BYTES = 4096
REQUEST_TIMEOUT_SECONDS = 20.0
MAX_REDIRECTS = 5

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_REQUIRED_DB_TABLES = frozenset(
    {
        "auth_events",
        "auth_principals",
        "auth_role_code_credentials",
        "auth_sessions",
        "common_ingested_events",
    }
)


class GateError(RuntimeError):
    """A sanitized contract or runtime failure."""

    def __init__(self, code: str):
        normalized = code if _SAFE_CODE_RE.fullmatch(code) else "INTERNAL_GATE_ERROR"
        self.code = normalized
        super().__init__(normalized)


class MissingRuntimeInput(GateError):
    """A deliberately absent deployment-window input (UNKNOWN, never PASS)."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise GateError(code)


def _exact_mapping(value: Any, keys: set[str], code: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping) and set(value) == keys, code)
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bounded_read(path: Path, maximum: int, code: str) -> bytes:
    require(path.is_file(), code)
    try:
        size = path.stat().st_size
        require(0 < size <= maximum, code)
        payload = path.read_bytes()
    except OSError as exc:
        raise GateError(code) from exc
    require(len(payload) == size and len(payload) <= maximum, code)
    return payload


def _load_json_bytes(payload: bytes, code: str) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(code) from exc
    require(isinstance(value, Mapping), code)
    return value


def _absolute_path(value: Any, code: str) -> Path:
    require(isinstance(value, str) and bool(value.strip()), code)
    path = Path(value)
    require(path.is_absolute(), code)
    return path


def _evidence_path(value: str) -> Path:
    path = _absolute_path(value, "EVIDENCE_PATH_INVALID")
    require(path.drive.casefold() == "e:", "EVIDENCE_PATH_NOT_ON_E_DRIVE")
    require(path.suffix.casefold() == ".json", "EVIDENCE_PATH_INVALID")
    require(not path.exists(), "EVIDENCE_PATH_NOT_FRESH")
    return path


@dataclass(frozen=True)
class OriginBinding:
    profile: str
    port: int
    database: Path
    login_mode: str


@dataclass(frozen=True)
class Binding:
    expected_commit: str
    connect_ip: str
    pinned_ca_pem: Path
    expected_leaf_der_sha256: str
    transport_gate_script: Path
    transport_gate_script_sha256: str
    transport_evidence: Path
    session_cookie_name: str
    origins: Mapping[str, OriginBinding]


@dataclass(frozen=True)
class OriginSecrets:
    active_access_code: str = field(repr=False)
    known_invalid_access_code: str = field(repr=False)
    expired_session_cookie: str = field(repr=False)


@dataclass(frozen=True)
class CredentialBundle:
    origins: Mapping[str, OriginSecrets] = field(repr=False)


def load_binding(path: Path) -> Binding:
    payload = _load_json_bytes(
        _bounded_read(path, MAX_BINDING_BYTES, "BINDING_FILE_INVALID"),
        "BINDING_FILE_INVALID",
    )
    top = _exact_mapping(
        payload,
        {
            "schema",
            "expected_commit",
            "connect_ip",
            "pinned_ca_pem",
            "expected_leaf_der_sha256",
            "transport_gate_script",
            "transport_gate_script_sha256",
            "transport_evidence",
            "session_cookie_name",
            "databases",
            "login_modes",
        },
        "BINDING_SHAPE_INVALID",
    )
    require(top["schema"] == BINDING_SCHEMA, "BINDING_SCHEMA_INVALID")
    expected_commit = str(top["expected_commit"])
    require(bool(_COMMIT_RE.fullmatch(expected_commit)), "EXPECTED_COMMIT_INVALID")
    try:
        connect_ip = str(ipaddress.ip_address(str(top["connect_ip"])))
    except ValueError as exc:
        raise GateError("CONNECT_IP_INVALID") from exc
    require(
        not ipaddress.ip_address(connect_ip).is_unspecified
        and not ipaddress.ip_address(connect_ip).is_multicast,
        "CONNECT_IP_INVALID",
    )
    leaf_sha = str(top["expected_leaf_der_sha256"]).casefold()
    script_sha = str(top["transport_gate_script_sha256"]).casefold()
    require(bool(_SHA256_RE.fullmatch(leaf_sha)), "EXPECTED_LEAF_SHA256_INVALID")
    require(bool(_SHA256_RE.fullmatch(script_sha)), "TRANSPORT_TOOL_SHA256_INVALID")
    cookie_name = str(top["session_cookie_name"])
    require(bool(_COOKIE_NAME_RE.fullmatch(cookie_name)), "SESSION_COOKIE_NAME_INVALID")
    databases = _exact_mapping(top["databases"], set(PROFILES), "DATABASE_BINDINGS_INVALID")
    login_modes = _exact_mapping(top["login_modes"], set(PROFILES), "LOGIN_MODES_INVALID")
    origins: dict[str, OriginBinding] = {}
    for profile, port in CANONICAL_PORTS.items():
        database = _absolute_path(databases[profile], "DATABASE_PATH_INVALID")
        mode = str(login_modes[profile])
        require(mode in {"standard", "emergency"}, "LOGIN_MODE_INVALID")
        origins[profile] = OriginBinding(profile, port, database, mode)
    return Binding(
        expected_commit=expected_commit,
        connect_ip=connect_ip,
        pinned_ca_pem=_absolute_path(top["pinned_ca_pem"], "PINNED_CA_PATH_INVALID"),
        expected_leaf_der_sha256=leaf_sha,
        transport_gate_script=_absolute_path(
            top["transport_gate_script"], "TRANSPORT_TOOL_PATH_INVALID"
        ),
        transport_gate_script_sha256=script_sha,
        transport_evidence=_absolute_path(
            top["transport_evidence"], "TRANSPORT_EVIDENCE_PATH_INVALID"
        ),
        session_cookie_name=cookie_name,
        origins=origins,
    )


def _secret_text(value: Any, code: str, *, maximum: int) -> str:
    require(isinstance(value, str), code)
    encoded = value.encode("utf-8")
    require(1 <= len(encoded) <= maximum and "\x00" not in value, code)
    return value


def load_credentials_from_stdin(stream: Any = None) -> CredentialBundle:
    source = stream if stream is not None else sys.stdin.buffer
    try:
        payload = source.read(MAX_CREDENTIAL_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise GateError("CREDENTIAL_STDIN_UNREADABLE") from exc
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    require(0 < len(payload) <= MAX_CREDENTIAL_BYTES, "CREDENTIAL_STDIN_SIZE_INVALID")
    value = _load_json_bytes(payload, "CREDENTIAL_JSON_INVALID")
    top = _exact_mapping(value, {"schema", "origins"}, "CREDENTIAL_SHAPE_INVALID")
    require(top["schema"] == CREDENTIAL_SCHEMA, "CREDENTIAL_SCHEMA_INVALID")
    origins = _exact_mapping(top["origins"], set(PROFILES), "CREDENTIAL_ORIGINS_INVALID")
    normalized: dict[str, OriginSecrets] = {}
    for profile in PROFILES:
        row = _exact_mapping(
            origins[profile],
            {
                "active_access_code",
                "known_invalid_access_code",
                "expired_session_cookie",
            },
            "CREDENTIAL_ORIGIN_SHAPE_INVALID",
        )
        active = _secret_text(row["active_access_code"], "ACTIVE_CREDENTIAL_INVALID", maximum=128)
        invalid = _secret_text(
            row["known_invalid_access_code"], "INVALID_CREDENTIAL_INVALID", maximum=128
        )
        expired = _secret_text(
            row["expired_session_cookie"], "EXPIRED_SESSION_COOKIE_INVALID", maximum=MAX_COOKIE_BYTES
        )
        require("\r" not in expired and "\n" not in expired and ";" not in expired, "EXPIRED_SESSION_COOKIE_INVALID")
        cookie_name, separator, cookie_value = expired.partition("=")
        require(bool(separator) and bool(cookie_value), "EXPIRED_SESSION_COOKIE_INVALID")
        require(bool(_COOKIE_NAME_RE.fullmatch(cookie_name)), "EXPIRED_SESSION_COOKIE_INVALID")
        require(not hmac.compare_digest(active, invalid), "NEGATIVE_CREDENTIAL_NOT_DISTINCT")
        normalized[profile] = OriginSecrets(active, invalid, expired)
    active_codes = [normalized[profile].active_access_code for profile in PROFILES]
    for index, left in enumerate(active_codes):
        for right in active_codes[index + 1 :]:
            require(not hmac.compare_digest(left, right), "ORIGIN_CREDENTIALS_NOT_DISTINCT")
    return CredentialBundle(normalized)


class _CsrfParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = {str(key).casefold(): value for key, value in attrs}
        if (
            tag.casefold() == "input"
            and values.get("name") == "csrf_token"
            and values.get("value")
        ):
            self.values.append(str(values["value"]))
        if (
            tag.casefold() == "meta"
            and values.get("name") == "csrf-token"
            and values.get("content")
        ):
            self.values.append(str(values["content"]))


def _csrf_token(body: bytes) -> str:
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise GateError("CSRF_PAGE_ENCODING_INVALID") from exc
    parser = _CsrfParser()
    parser.feed(text)
    parser.close()
    values = set(parser.values)
    require(len(values) == 1, "CSRF_TOKEN_CONTRACT_INVALID")
    return next(iter(values))


@dataclass(frozen=True)
class HttpObservation:
    status: int
    final_path: str
    source_commit_match: bool
    content_type: str
    body: bytes = field(repr=False)
    set_cookie_headers: tuple[str, ...] = field(repr=False, default=())

    def evidence(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "final_path": self.final_path,
            "source_commit_match": self.source_commit_match,
            "content_type": self.content_type,
            "body_bytes": len(self.body),
        }


@dataclass(frozen=True)
class LoginObservation:
    accepted: bool
    response: HttpObservation
    cookie_contract: Mapping[str, bool]
    session_cookie_header: str | None = field(repr=False)


class OriginClientProtocol(Protocol):
    def login(self, access_code: str) -> LoginObservation: ...

    def catalog(self) -> HttpObservation: ...

    def catalog_with_cookie(self, cookie_header: str) -> HttpObservation: ...

    def logout_and_reprobe(self) -> tuple[HttpObservation, HttpObservation]: ...


class OriginClient:
    """Small no-proxy TLS client with an origin-local in-memory cookie jar."""

    def __init__(self, binding: Binding, origin: OriginBinding):
        self.binding = binding
        self.origin = origin
        self.cookies: dict[str, str] = {}
        self._last_root_body: bytes | None = None
        ca_data = _bounded_read(binding.pinned_ca_pem, MAX_CA_BYTES, "PINNED_CA_INVALID")
        require(b"PRIVATE KEY" not in ca_data.upper(), "PINNED_CA_INVALID")
        try:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.check_hostname = True
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.context.load_verify_locations(cadata=ca_data.decode("ascii"))
        except (UnicodeDecodeError, ssl.SSLError) as exc:
            raise GateError("PINNED_CA_INVALID") from exc

    def _cookie_header(self) -> str | None:
        if not self.cookies:
            return None
        return "; ".join(f"{name}={value}" for name, value in sorted(self.cookies.items()))

    def _apply_set_cookie(self, header: str) -> None:
        if len(header.encode("utf-8")) > MAX_COOKIE_BYTES:
            raise GateError("SET_COOKIE_HEADER_INVALID")
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except CookieError as exc:
            raise GateError("SET_COOKIE_HEADER_INVALID") from exc
        require(bool(parsed), "SET_COOKIE_HEADER_INVALID")
        for name, morsel in parsed.items():
            if morsel.value and morsel["max-age"] != "0":
                self.cookies[name] = morsel.value
            else:
                self.cookies.pop(name, None)

    def _single_request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        cookie_override: str | None = None,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        raw_socket: socket.socket | None = None
        tls_socket: ssl.SSLSocket | None = None
        connection: http.client.HTTPConnection | None = None
        try:
            raw_socket = socket.create_connection(
                (self.binding.connect_ip, self.origin.port), timeout=REQUEST_TIMEOUT_SECONDS
            )
            tls_socket = self.context.wrap_socket(raw_socket, server_hostname=HOST)
            raw_socket = None
            peer_der = tls_socket.getpeercert(binary_form=True)
            require(bool(peer_der), "TLS_PEER_CERTIFICATE_MISSING")
            require(
                _sha256_bytes(peer_der) == self.binding.expected_leaf_der_sha256,
                "TLS_LEAF_DER_SHA256_MISMATCH",
            )
            connection = http.client.HTTPConnection(HOST, self.origin.port, timeout=REQUEST_TIMEOUT_SECONDS)
            connection.sock = tls_socket
            tls_socket = None
            headers = {
                "Host": f"{HOST}:{self.origin.port}",
                "User-Agent": "KMTech-Authenticated-O3/1",
                "Accept": "*/*",
                "Connection": "close",
            }
            cookie_header = cookie_override if cookie_override is not None else self._cookie_header()
            if cookie_header:
                headers["Cookie"] = cookie_header
            if body is not None:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                headers["Content-Length"] = str(len(body))
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response_headers = [(str(name), str(value)) for name, value in response.getheaders()]
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            require(len(response_body) <= MAX_RESPONSE_BYTES, "HTTP_RESPONSE_TOO_LARGE")
            return int(response.status), response_headers, response_body
        except GateError:
            raise
        except ssl.SSLCertVerificationError as exc:
            raise GateError("TLS_CERTIFICATE_VERIFICATION_FAILED") from exc
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise GateError("ORIGIN_REQUEST_FAILED") from exc
        finally:
            if connection is not None:
                connection.close()
            elif tls_socket is not None:
                tls_socket.close()
            elif raw_socket is not None:
                raw_socket.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        cookie_override: str | None = None,
    ) -> HttpObservation:
        current_method = method
        current_path = path
        current_body = body
        all_set_cookie: list[str] = []
        for _redirect in range(MAX_REDIRECTS + 1):
            status, headers, response_body = self._single_request(
                current_method,
                current_path,
                body=current_body,
                cookie_override=cookie_override,
            )
            normalized: dict[str, list[str]] = {}
            for name, value in headers:
                normalized.setdefault(name.casefold(), []).append(value)
            set_cookie = normalized.get("set-cookie", [])
            all_set_cookie.extend(set_cookie)
            if cookie_override is None:
                for header in set_cookie:
                    self._apply_set_cookie(header)
            source_values = normalized.get(SOURCE_COMMIT_HEADER.casefold(), [])
            source_match = (
                len(source_values) == 1
                and source_values[0].strip() == self.binding.expected_commit
            )
            content_type = normalized.get("content-type", [""])[-1]
            if status not in {301, 302, 303, 307, 308}:
                final_path = urllib.parse.urlsplit(current_path).path or "/"
                return HttpObservation(
                    status,
                    final_path,
                    source_match,
                    content_type,
                    response_body,
                    tuple(all_set_cookie),
                )
            locations = normalized.get("location", [])
            require(len(locations) == 1, "REDIRECT_LOCATION_INVALID")
            destination = urllib.parse.urlsplit(
                urllib.parse.urljoin(f"https://{HOST}:{self.origin.port}{current_path}", locations[0])
            )
            require(
                destination.scheme.casefold() == "https"
                and (destination.hostname or "").casefold() == HOST.casefold()
                and int(destination.port or 443) == self.origin.port
                and destination.username is None
                and destination.password is None
                and not destination.fragment,
                "REDIRECT_LEFT_ORIGIN",
            )
            current_path = destination.path or "/"
            if destination.query:
                current_path += "?" + destination.query
            if status == 303 or (status in {301, 302} and current_method == "POST"):
                current_method = "GET"
                current_body = None
        raise GateError("REDIRECT_LIMIT_EXCEEDED")

    def login(self, access_code: str) -> LoginObservation:
        login_page = self._request("GET", "/login?next=/")
        require(
            login_page.status == 200
            and login_page.final_path == "/login"
            and login_page.source_commit_match,
            "LOGIN_PAGE_CONTRACT_INVALID",
        )
        csrf = _csrf_token(login_page.body)
        before_cookie = self.cookies.get(self.binding.session_cookie_name)
        form = urllib.parse.urlencode({"code": access_code, "csrf_token": csrf}).encode("ascii")
        login_path = (
            "/login/emergency?next=/"
            if self.origin.login_mode == "emergency"
            else "/login?next=/"
        )
        response = self._request("POST", login_path, body=form)
        current_cookie = self.cookies.get(self.binding.session_cookie_name)
        accepted = bool(
            response.status == 200
            and response.final_path == "/"
            and response.source_commit_match
            and current_cookie
            and current_cookie != before_cookie
        )
        cookie_contract = self._cookie_contract(response.set_cookie_headers, before_cookie)
        if accepted:
            self._last_root_body = response.body
        header = (
            f"{self.binding.session_cookie_name}={current_cookie}"
            if accepted and current_cookie
            else None
        )
        return LoginObservation(accepted, response, cookie_contract, header)

    def _cookie_contract(
        self, headers: Sequence[str], before_cookie: str | None
    ) -> Mapping[str, bool]:
        matches: list[Any] = []
        for header in headers:
            parsed = SimpleCookie()
            try:
                parsed.load(header)
            except CookieError:
                continue
            if self.binding.session_cookie_name in parsed:
                matches.append(parsed[self.binding.session_cookie_name])
        current = self.cookies.get(self.binding.session_cookie_name)
        morsel = matches[-1] if matches else None
        return {
            "session_cookie_present": bool(current),
            "session_cookie_rotated": bool(current and current != before_cookie),
            "secure": bool(morsel and morsel["secure"]),
            "http_only": bool(morsel and morsel["httponly"]),
            "same_site_lax": bool(morsel and morsel["samesite"].casefold() == "lax"),
            "path_root": bool(morsel and morsel["path"] == "/"),
            "host_only": bool(morsel and not morsel["domain"]),
        }

    def catalog(self) -> HttpObservation:
        return self._request("GET", CATALOG_PATH)

    def catalog_with_cookie(self, cookie_header: str) -> HttpObservation:
        require(
            isinstance(cookie_header, str)
            and 0 < len(cookie_header.encode("utf-8")) <= MAX_COOKIE_BYTES
            and "\r" not in cookie_header
            and "\n" not in cookie_header
            and ";" not in cookie_header,
            "COOKIE_OVERRIDE_INVALID",
        )
        return self._request("GET", CATALOG_PATH, cookie_override=cookie_header)

    def logout_and_reprobe(self) -> tuple[HttpObservation, HttpObservation]:
        root = self._request("GET", "/")
        require(
            root.status == 200 and root.final_path == "/" and root.source_commit_match,
            "AUTHENTICATED_ROOT_INVALID",
        )
        csrf = _csrf_token(root.body)
        prior_cookie = self.cookies.get(self.binding.session_cookie_name)
        require(bool(prior_cookie), "AUTHENTICATED_SESSION_COOKIE_MISSING")
        body = urllib.parse.urlencode({"csrf_token": csrf}).encode("ascii")
        logout = self._request("POST", "/logout", body=body)
        old_cookie_header = f"{self.binding.session_cookie_name}={prior_cookie}"
        reprobe = self.catalog_with_cookie(old_cookie_header)
        return logout, reprobe


def _item(
    item_id: str,
    profile: str | None,
    status: str,
    reason: str,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    require(status in {"PASS", "FAIL", "UNKNOWN"}, "ITEM_STATUS_INVALID")
    require(bool(_SAFE_CODE_RE.fullmatch(reason)), "ITEM_REASON_INVALID")
    stateful_suffixes = (
        ".auth_success",
        ".cookie_contract",
        ".wrong_credential_rejected",
        ".foreign_credentials_rejected",
        ".logout_rejected_old_session",
        ".cleanup_reauthentication",
    )
    state_change = bool(
        item_id.startswith("auth.") or item_id.endswith(stateful_suffixes)
    )
    return {
        "item_id": item_id,
        "profile": profile,
        "status": status,
        "reason": reason,
        "state_change": SIDE_EFFECT_CLASS if state_change else "NONE_DIRECT",
        "evidence": dict(evidence or {}),
    }


def _profile_item_id(profile: str, suffix: str) -> str:
    return f"{profile}.{suffix}"


def _all_item_specs() -> list[tuple[str, str | None]]:
    specs: list[tuple[str, str | None]] = [
        ("transport.baseline", None),
        ("auth.credential_contract", None),
        ("auth.state_change_approval", None),
        ("auth.cookie_values_distinct", None),
    ]
    suffixes = (
        "listener_pid",
        "database_before",
        "auth_success",
        "cookie_contract",
        "catalog_authenticated",
        "wrong_credential_rejected",
        "expired_session_rejected",
        "foreign_credentials_rejected",
        "foreign_sessions_rejected",
        "logout_rejected_old_session",
        "cleanup_reauthentication",
        "database_after",
    )
    for profile in PROFILES:
        specs.extend((_profile_item_id(profile, suffix), profile) for suffix in suffixes)
    return specs


def _overall(items: Sequence[Mapping[str, Any]]) -> str:
    statuses = [str(item.get("status")) for item in items]
    if "FAIL" in statuses:
        return "FAIL"
    if not statuses or "UNKNOWN" in statuses or any(
        status not in {"PASS", "FAIL", "UNKNOWN"} for status in statuses
    ):
        return "UNKNOWN"
    return "PASS"


def _document(mode: str, items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    status = _overall(items)
    counts = {value: sum(item["status"] == value for item in items) for value in ("PASS", "FAIL", "UNKNOWN")}
    return {
        "schema": SCHEMA,
        "gate": GATE,
        "mode": mode,
        "overall_status": status,
        "unknown_is_not_pass": True,
        "credentials_emitted": False,
        "cookies_emitted": False,
        "response_bodies_emitted": False,
        "server_restart_or_configuration_change": False,
        "business_state_write_requested": False,
        "state_change": {
            "performed": mode == "live",
            "class": SIDE_EFFECT_CLASS if mode == "live" else "NONE",
            "operator_acknowledgement_required": True,
        },
        "profiles": {profile: {"port": CANONICAL_PORTS[profile]} for profile in PROFILES},
        "item_counts": counts,
        "items": list(items),
    }


def dry_run_document(reason: str = "RUNTIME_INPUT_NOT_SUPPLIED") -> dict[str, Any]:
    items = [
        _item(item_id, profile, "UNKNOWN", reason)
        for item_id, profile in _all_item_specs()
    ]
    return _document("dry-run", items)


def failure_document(code: str) -> dict[str, Any]:
    items = []
    for index, (item_id, profile) in enumerate(_all_item_specs()):
        items.append(
            _item(
                item_id,
                profile,
                "FAIL" if index == 0 else "UNKNOWN",
                code if index == 0 else "DEPENDENCY_FAILED",
            )
        )
    return _document("input-failure", items)


def validate_transport_baseline(binding: Binding) -> tuple[dict[str, Any], Mapping[str, Any]]:
    script_data = _bounded_read(
        binding.transport_gate_script, 512 * 1024, "TRANSPORT_TOOL_INVALID"
    )
    require(
        _sha256_bytes(script_data) == binding.transport_gate_script_sha256,
        "TRANSPORT_TOOL_SHA256_MISMATCH",
    )
    evidence_data = _bounded_read(
        binding.transport_evidence,
        MAX_TRANSPORT_EVIDENCE_BYTES,
        "TRANSPORT_EVIDENCE_INVALID",
    )
    evidence = _load_json_bytes(evidence_data, "TRANSPORT_EVIDENCE_INVALID")
    try:
        spec = importlib.util.spec_from_file_location(
            "_kmtech_three_origin_gate_frozen", binding.transport_gate_script
        )
        require(spec is not None and spec.loader is not None, "TRANSPORT_TOOL_IMPORT_FAILED")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
        validator = getattr(module, "validate_gate_evidence", None)
        require(callable(validator), "TRANSPORT_TOOL_VALIDATOR_MISSING")
        expected = _exact_mapping(
            evidence.get("expected"),
            {
                "host",
                "ports",
                "source_commit",
                "connect_ip",
                "leaf_der_sha256",
                "pinned_ca_pem_sha256",
            },
            "TRANSPORT_EVIDENCE_INVALID",
        )
        receipts = _exact_mapping(
            evidence.get("start_receipts"), set(PROFILES), "TRANSPORT_EVIDENCE_INVALID"
        )
        validator(
            evidence,
            expected_commit=binding.expected_commit,
            connect_ip=binding.connect_ip,
            expected_leaf_der_sha256=binding.expected_leaf_der_sha256,
            pinned_ca_pem_sha256=str(expected["pinned_ca_pem_sha256"]),
            expected_receipts=receipts,
        )
    except GateError:
        raise
    except Exception as exc:
        raise GateError("TRANSPORT_EVIDENCE_INVALID") from exc
    return (
        {
            "transport_tool_sha256": binding.transport_gate_script_sha256,
            "transport_evidence_sha256": _sha256_bytes(evidence_data),
            "source_commit": binding.expected_commit,
            "connect_ip": binding.connect_ip,
        },
        evidence,
    )


def database_gate(path: Path) -> dict[str, Any]:
    require(path.is_file(), "DATABASE_FILE_MISSING")
    try:
        uri = f"file:{urllib.parse.quote(path.as_posix(), safe='/:')}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=10.0)
        try:
            connection.execute("PRAGMA query_only=ON")
            query_only = int(connection.execute("PRAGMA query_only").fetchone()[0])
            quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise GateError("DATABASE_QUERY_FAILED") from exc
    missing = sorted(_REQUIRED_DB_TABLES - tables)
    require(query_only == 1 and quick_check == ["ok"], "DATABASE_QUICK_CHECK_FAILED")
    require(not missing, "DATABASE_REQUIRED_TABLES_MISSING")
    return {
        "query_only": True,
        "quick_check": "ok",
        "required_table_count": len(_REQUIRED_DB_TABLES),
        "missing_required_table_count": 0,
    }


def _catalog_pass(observation: HttpObservation) -> tuple[bool, dict[str, Any]]:
    evidence = observation.evidence()
    rows = 0
    header_matches = False
    try:
        decoded = observation.body.decode("utf-8-sig", errors="strict")
        parsed = list(csv.reader(io.StringIO(decoded)))
        header_matches = bool(parsed) and tuple(parsed[0]) == CATALOG_HEADER
        rows = max(0, len(parsed) - 1)
    except (UnicodeDecodeError, csv.Error):
        pass
    media_type = observation.content_type.split(";", 1)[0].strip().casefold()
    passed = bool(
        observation.status == 200
        and observation.final_path == CATALOG_PATH
        and observation.source_commit_match
        and media_type == "text/csv"
        and header_matches
        and rows > 0
    )
    evidence.update({"header_matches": header_matches, "catalog_rows": rows})
    return passed, evidence


def _rejected(observation: HttpObservation) -> bool:
    return bool(
        observation.source_commit_match
        and (
            observation.status in {401, 403}
            or (observation.status == 200 and observation.final_path == "/login")
        )
    )


ClientFactory = Callable[[Binding, OriginBinding], OriginClientProtocol]


def run_live(
    binding: Binding,
    credentials: CredentialBundle,
    *,
    client_factory: ClientFactory = OriginClient,
    transport_validator: Callable[
        [Binding], tuple[dict[str, Any], Mapping[str, Any]]
    ] = validate_transport_baseline,
    database_probe: Callable[[Path], dict[str, Any]] = database_gate,
) -> dict[str, Any]:
    for profile in PROFILES:
        expired_name = credentials.origins[profile].expired_session_cookie.partition("=")[0]
        require(
            hmac.compare_digest(expired_name, binding.session_cookie_name),
            "EXPIRED_SESSION_COOKIE_NAME_MISMATCH",
        )
    results: dict[str, dict[str, Any]] = {}

    try:
        transport_summary, transport_evidence = transport_validator(binding)
        results["transport.baseline"] = _item(
            "transport.baseline", None, "PASS", "TRANSPORT_BASELINE_VALID", transport_summary
        )
        listener_after = _exact_mapping(
            _exact_mapping(
                transport_evidence.get("listener_checks"),
                {"before_origin_probes", "after_origin_probes"},
                "TRANSPORT_EVIDENCE_INVALID",
            )["after_origin_probes"],
            set(PROFILES),
            "TRANSPORT_EVIDENCE_INVALID",
        )
        receipts = _exact_mapping(
            transport_evidence.get("start_receipts"), set(PROFILES), "TRANSPORT_EVIDENCE_INVALID"
        )
        for profile in PROFILES:
            listener = listener_after[profile]
            receipt = receipts[profile]
            results[_profile_item_id(profile, "listener_pid")] = _item(
                _profile_item_id(profile, "listener_pid"),
                profile,
                "PASS",
                "LISTENER_PID_BASELINE_VALID",
                {
                    "port": CANONICAL_PORTS[profile],
                    "pid": int(listener["owning_pid"]),
                    "bind": str(receipt["bind"]),
                    "receipt_sha256": str(receipt["receipt_sha256"]),
                },
            )
    except GateError as exc:
        results["transport.baseline"] = _item(
            "transport.baseline", None, "FAIL", exc.code
        )
        for profile in PROFILES:
            results[_profile_item_id(profile, "listener_pid")] = _item(
                _profile_item_id(profile, "listener_pid"), profile, "UNKNOWN", "DEPENDENCY_FAILED"
            )

    results["auth.credential_contract"] = _item(
        "auth.credential_contract",
        None,
        "PASS",
        "CREDENTIAL_STDIN_CONTRACT_VALID",
        {"profiles": len(credentials.origins), "values_emitted": False},
    )
    results["auth.state_change_approval"] = _item(
        "auth.state_change_approval",
        None,
        "PASS",
        "AUTH_STATE_CHANGE_APPROVED",
        {"acknowledgement": ACKNOWLEDGEMENT, "side_effect_class": SIDE_EFFECT_CLASS},
    )

    db_ready: dict[str, bool] = {}
    for profile in PROFILES:
        try:
            evidence = database_probe(binding.origins[profile].database)
            results[_profile_item_id(profile, "database_before")] = _item(
                _profile_item_id(profile, "database_before"),
                profile,
                "PASS",
                "DATABASE_READONLY_GATE_VALID",
                evidence,
            )
            db_ready[profile] = True
        except GateError as exc:
            results[_profile_item_id(profile, "database_before")] = _item(
                _profile_item_id(profile, "database_before"), profile, "FAIL", exc.code
            )
            db_ready[profile] = False

    positive_clients: dict[str, OriginClientProtocol] = {}
    positive_logins: dict[str, LoginObservation] = {}
    for profile in PROFILES:
        if results["transport.baseline"]["status"] != "PASS" or not db_ready[profile]:
            for suffix in ("auth_success", "cookie_contract", "catalog_authenticated"):
                results[_profile_item_id(profile, suffix)] = _item(
                    _profile_item_id(profile, suffix), profile, "UNKNOWN", "DEPENDENCY_FAILED"
                )
            continue
        try:
            client = client_factory(binding, binding.origins[profile])
            login = client.login(credentials.origins[profile].active_access_code)
            positive_clients[profile] = client
            positive_logins[profile] = login
            results[_profile_item_id(profile, "auth_success")] = _item(
                _profile_item_id(profile, "auth_success"),
                profile,
                "PASS" if login.accepted else "FAIL",
                "AUTHENTICATION_ACCEPTED" if login.accepted else "ACTIVE_CREDENTIAL_REJECTED",
                login.response.evidence(),
            )
            cookie_ok = bool(login.accepted and all(login.cookie_contract.values()))
            results[_profile_item_id(profile, "cookie_contract")] = _item(
                _profile_item_id(profile, "cookie_contract"),
                profile,
                "PASS" if cookie_ok else "FAIL",
                "COOKIE_CONTRACT_VALID" if cookie_ok else "COOKIE_CONTRACT_INVALID",
                dict(login.cookie_contract),
            )
            if login.accepted:
                catalog = client.catalog()
                catalog_ok, catalog_evidence = _catalog_pass(catalog)
                results[_profile_item_id(profile, "catalog_authenticated")] = _item(
                    _profile_item_id(profile, "catalog_authenticated"),
                    profile,
                    "PASS" if catalog_ok else "FAIL",
                    "AUTHENTICATED_CATALOG_VALID" if catalog_ok else "AUTHENTICATED_CATALOG_INVALID",
                    catalog_evidence,
                )
            else:
                results[_profile_item_id(profile, "catalog_authenticated")] = _item(
                    _profile_item_id(profile, "catalog_authenticated"),
                    profile,
                    "UNKNOWN",
                    "DEPENDENCY_FAILED",
                )
        except GateError as exc:
            for suffix in ("auth_success", "cookie_contract", "catalog_authenticated"):
                results[_profile_item_id(profile, suffix)] = _item(
                    _profile_item_id(profile, suffix),
                    profile,
                    "FAIL" if suffix == "auth_success" else "UNKNOWN",
                    exc.code if suffix == "auth_success" else "DEPENDENCY_FAILED",
                )

    active_cookie_headers = {
        profile: login.session_cookie_header
        for profile, login in positive_logins.items()
        if login.accepted and login.session_cookie_header
    }
    cookie_headers = list(active_cookie_headers.values())
    cookies_distinct = len(cookie_headers) == len(PROFILES) and len(set(cookie_headers)) == len(PROFILES)
    results["auth.cookie_values_distinct"] = _item(
        "auth.cookie_values_distinct",
        None,
        "PASS" if cookies_distinct else ("FAIL" if len(cookie_headers) == len(PROFILES) else "UNKNOWN"),
        "ORIGIN_SESSION_COOKIES_DISTINCT" if cookies_distinct else (
            "ORIGIN_SESSION_COOKIES_NOT_DISTINCT" if len(cookie_headers) == len(PROFILES) else "DEPENDENCY_FAILED"
        ),
        {"observed_profile_count": len(cookie_headers), "cookie_values_emitted": False},
    )

    for profile in PROFILES:
        if profile not in positive_clients or not positive_logins[profile].accepted:
            results[_profile_item_id(profile, "foreign_sessions_rejected")] = _item(
                _profile_item_id(profile, "foreign_sessions_rejected"), profile, "UNKNOWN", "DEPENDENCY_FAILED"
            )
            results[_profile_item_id(profile, "logout_rejected_old_session")] = _item(
                _profile_item_id(profile, "logout_rejected_old_session"), profile, "UNKNOWN", "DEPENDENCY_FAILED"
            )
            continue
        foreign_cookie_results: list[bool] = []
        foreign_evidence: list[dict[str, Any]] = []
        try:
            for source_profile, cookie_header in active_cookie_headers.items():
                if source_profile == profile:
                    continue
                isolated = client_factory(binding, binding.origins[profile])
                observed = isolated.catalog_with_cookie(cookie_header)
                foreign_cookie_results.append(_rejected(observed))
                foreign_evidence.append(
                    {"source_profile": source_profile, **observed.evidence()}
                )
            passed = len(foreign_cookie_results) == len(PROFILES) - 1 and all(foreign_cookie_results)
            results[_profile_item_id(profile, "foreign_sessions_rejected")] = _item(
                _profile_item_id(profile, "foreign_sessions_rejected"),
                profile,
                "PASS" if passed else "FAIL",
                "FOREIGN_SESSIONS_REJECTED" if passed else "FOREIGN_SESSION_ACCEPTED",
                {"attempts": foreign_evidence, "cookie_values_emitted": False},
            )
        except GateError as exc:
            results[_profile_item_id(profile, "foreign_sessions_rejected")] = _item(
                _profile_item_id(profile, "foreign_sessions_rejected"), profile, "FAIL", exc.code
            )
        try:
            logout, reprobe = positive_clients[profile].logout_and_reprobe()
            passed = bool(
                logout.status == 200
                and logout.final_path == "/login"
                and logout.source_commit_match
                and _rejected(reprobe)
            )
            results[_profile_item_id(profile, "logout_rejected_old_session")] = _item(
                _profile_item_id(profile, "logout_rejected_old_session"),
                profile,
                "PASS" if passed else "FAIL",
                "LOGOUT_REVOKED_SESSION" if passed else "LOGOUT_SESSION_STILL_ACCEPTED",
                {"logout": logout.evidence(), "old_session_reprobe": reprobe.evidence()},
            )
        except GateError as exc:
            results[_profile_item_id(profile, "logout_rejected_old_session")] = _item(
                _profile_item_id(profile, "logout_rejected_old_session"), profile, "FAIL", exc.code
            )

    for profile in PROFILES:
        if results["transport.baseline"]["status"] != "PASS":
            for suffix in (
                "wrong_credential_rejected",
                "expired_session_rejected",
                "foreign_credentials_rejected",
                "cleanup_reauthentication",
            ):
                results[_profile_item_id(profile, suffix)] = _item(
                    _profile_item_id(profile, suffix), profile, "UNKNOWN", "DEPENDENCY_FAILED"
                )
            continue
        try:
            wrong_client = client_factory(binding, binding.origins[profile])
            wrong_login = wrong_client.login(credentials.origins[profile].known_invalid_access_code)
            wrong_catalog = wrong_client.catalog()
            passed = not wrong_login.accepted and _rejected(wrong_catalog)
            results[_profile_item_id(profile, "wrong_credential_rejected")] = _item(
                _profile_item_id(profile, "wrong_credential_rejected"),
                profile,
                "PASS" if passed else "FAIL",
                "WRONG_CREDENTIAL_REJECTED" if passed else "WRONG_CREDENTIAL_ACCEPTED",
                {"login": wrong_login.response.evidence(), "protected_reprobe": wrong_catalog.evidence()},
            )
        except GateError as exc:
            results[_profile_item_id(profile, "wrong_credential_rejected")] = _item(
                _profile_item_id(profile, "wrong_credential_rejected"), profile, "FAIL", exc.code
            )
        try:
            expired_client = client_factory(binding, binding.origins[profile])
            expired = expired_client.catalog_with_cookie(
                credentials.origins[profile].expired_session_cookie
            )
            passed = _rejected(expired)
            results[_profile_item_id(profile, "expired_session_rejected")] = _item(
                _profile_item_id(profile, "expired_session_rejected"),
                profile,
                "PASS" if passed else "FAIL",
                "EXPIRED_SESSION_REJECTED" if passed else "EXPIRED_SESSION_ACCEPTED",
                expired.evidence(),
            )
        except GateError as exc:
            results[_profile_item_id(profile, "expired_session_rejected")] = _item(
                _profile_item_id(profile, "expired_session_rejected"), profile, "FAIL", exc.code
            )
        foreign_attempts: list[dict[str, Any]] = []
        foreign_pass = True
        try:
            for source_profile in PROFILES:
                if source_profile == profile:
                    continue
                foreign_client = client_factory(binding, binding.origins[profile])
                observed_login = foreign_client.login(
                    credentials.origins[source_profile].active_access_code
                )
                observed_catalog = foreign_client.catalog()
                rejected = not observed_login.accepted and _rejected(observed_catalog)
                foreign_pass = foreign_pass and rejected
                foreign_attempts.append(
                    {
                        "source_profile": source_profile,
                        "login": observed_login.response.evidence(),
                        "protected_reprobe": observed_catalog.evidence(),
                    }
                )
            results[_profile_item_id(profile, "foreign_credentials_rejected")] = _item(
                _profile_item_id(profile, "foreign_credentials_rejected"),
                profile,
                "PASS" if foreign_pass else "FAIL",
                "FOREIGN_CREDENTIALS_REJECTED" if foreign_pass else "FOREIGN_CREDENTIAL_ACCEPTED",
                {"attempts": foreign_attempts, "credential_values_emitted": False},
            )
        except GateError as exc:
            results[_profile_item_id(profile, "foreign_credentials_rejected")] = _item(
                _profile_item_id(profile, "foreign_credentials_rejected"), profile, "FAIL", exc.code
            )
        try:
            cleanup_client = client_factory(binding, binding.origins[profile])
            cleanup_login = cleanup_client.login(credentials.origins[profile].active_access_code)
            if cleanup_login.accepted:
                cleanup_logout, cleanup_reprobe = cleanup_client.logout_and_reprobe()
                cleanup_pass = bool(
                    cleanup_logout.status == 200
                    and cleanup_logout.final_path == "/login"
                    and _rejected(cleanup_reprobe)
                )
            else:
                cleanup_pass = False
            results[_profile_item_id(profile, "cleanup_reauthentication")] = _item(
                _profile_item_id(profile, "cleanup_reauthentication"),
                profile,
                "PASS" if cleanup_pass else "FAIL",
                "AUTH_THROTTLE_CLEANUP_CONFIRMED" if cleanup_pass else "AUTH_THROTTLE_CLEANUP_FAILED",
                {"login": cleanup_login.response.evidence()},
            )
        except GateError as exc:
            results[_profile_item_id(profile, "cleanup_reauthentication")] = _item(
                _profile_item_id(profile, "cleanup_reauthentication"), profile, "FAIL", exc.code
            )

    for profile in PROFILES:
        try:
            evidence = database_probe(binding.origins[profile].database)
            results[_profile_item_id(profile, "database_after")] = _item(
                _profile_item_id(profile, "database_after"),
                profile,
                "PASS",
                "DATABASE_READONLY_GATE_VALID",
                evidence,
            )
        except GateError as exc:
            results[_profile_item_id(profile, "database_after")] = _item(
                _profile_item_id(profile, "database_after"), profile, "FAIL", exc.code
            )

    ordered = [results.get(item_id) for item_id, _profile in _all_item_specs()]
    final_items: list[Mapping[str, Any]] = []
    for (item_id, profile), result in zip(_all_item_specs(), ordered):
        final_items.append(
            result
            if result is not None
            else _item(item_id, profile, "UNKNOWN", "ITEM_NOT_MEASURED")
        )
    return _document("live", final_items)


def validate_evidence_document(value: Mapping[str, Any]) -> None:
    top = _exact_mapping(
        value,
        {
            "schema",
            "gate",
            "mode",
            "overall_status",
            "unknown_is_not_pass",
            "credentials_emitted",
            "cookies_emitted",
            "response_bodies_emitted",
            "server_restart_or_configuration_change",
            "business_state_write_requested",
            "state_change",
            "profiles",
            "item_counts",
            "items",
        },
        "EVIDENCE_SHAPE_INVALID",
    )
    require(top["schema"] == SCHEMA and top["gate"] == GATE, "EVIDENCE_IDENTITY_INVALID")
    require(top["mode"] in {"dry-run", "live", "input-failure"}, "EVIDENCE_MODE_INVALID")
    require(top["unknown_is_not_pass"] is True, "EVIDENCE_FAIL_CLOSED_INVALID")
    require(
        top["credentials_emitted"] is False
        and top["cookies_emitted"] is False
        and top["response_bodies_emitted"] is False,
        "SECRET_EMISSION_CONTRACT_INVALID",
    )
    require(
        top["server_restart_or_configuration_change"] is False
        and top["business_state_write_requested"] is False,
        "MUTATION_CONTRACT_INVALID",
    )
    profiles = _exact_mapping(top["profiles"], set(PROFILES), "PROFILE_SET_INVALID")
    for profile, port in CANONICAL_PORTS.items():
        row = _exact_mapping(profiles[profile], {"port"}, "PROFILE_SHAPE_INVALID")
        require(row["port"] == port, "PROFILE_PORT_INVALID")
    items = top["items"]
    require(isinstance(items, list), "EVIDENCE_ITEMS_INVALID")
    expected_specs = _all_item_specs()
    require(len(items) == len(expected_specs), "EVIDENCE_ITEM_COUNT_INVALID")
    by_id: dict[str, Mapping[str, Any]] = {}
    for raw in items:
        item = _exact_mapping(
            raw,
            {"item_id", "profile", "status", "reason", "state_change", "evidence"},
            "EVIDENCE_ITEM_SHAPE_INVALID",
        )
        item_id = str(item["item_id"])
        require(item_id not in by_id, "EVIDENCE_ITEM_DUPLICATE")
        require(item["status"] in {"PASS", "FAIL", "UNKNOWN"}, "EVIDENCE_ITEM_STATUS_INVALID")
        require(bool(_SAFE_CODE_RE.fullmatch(str(item["reason"]))), "EVIDENCE_ITEM_REASON_INVALID")
        require(isinstance(item["evidence"], Mapping), "EVIDENCE_ITEM_PAYLOAD_INVALID")
        by_id[item_id] = item
    require(set(by_id) == {item_id for item_id, _ in expected_specs}, "EVIDENCE_ITEM_SET_INVALID")
    for item_id, profile in expected_specs:
        require(by_id[item_id]["profile"] == profile, "EVIDENCE_ITEM_PROFILE_INVALID")
    overall = _overall(items)
    require(top["overall_status"] == overall, "EVIDENCE_OVERALL_STATUS_INVALID")
    counts = _exact_mapping(top["item_counts"], {"PASS", "FAIL", "UNKNOWN"}, "EVIDENCE_COUNTS_INVALID")
    for status in ("PASS", "FAIL", "UNKNOWN"):
        require(counts[status] == sum(item["status"] == status for item in items), "EVIDENCE_COUNTS_INVALID")


def selected_status(value: Mapping[str, Any], profile: str) -> str:
    validate_evidence_document(value)
    require(profile in {*PROFILES, "all"}, "VALIDATION_PROFILE_INVALID")
    items = value["items"]
    if profile == "all":
        return _overall(items)
    selected = [item for item in items if item["profile"] in {None, profile}]
    return _overall(selected)


def atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    require(not path.exists(), "EVIDENCE_PATH_NOT_FRESH")
    try:
        serialized = json.dumps(
            payload, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise GateError("EVIDENCE_SERIALIZATION_FAILED") from exc
    require(len(serialized) <= MAX_EVIDENCE_BYTES, "EVIDENCE_TOO_LARGE")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    except FileExistsError as exc:
        raise GateError("EVIDENCE_PATH_NOT_FRESH") from exc
    except OSError as exc:
        raise GateError("EVIDENCE_WRITE_FAILED") from exc


class StopParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - argparse owns text
        del message
        raise GateError("ARGUMENTS_INVALID")


def build_parser() -> argparse.ArgumentParser:
    parser = StopParser(description="Authenticated three-origin qualification gate")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    dry = subparsers.add_parser("dry-run")
    dry.add_argument("--evidence", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--binding", required=True)
    run.add_argument("--credentials-stdin", action="store_true")
    run.add_argument("--ack-auth-state-change", default="")
    run.add_argument("--evidence", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--input-evidence", required=True)
    validate.add_argument("--profile", required=True, choices=(*PROFILES, "all"))
    return parser


def _pointer(status: str, evidence: Path, profile: str) -> dict[str, Any]:
    return {
        "schema": POINTER_SCHEMA,
        "overall_status": status,
        "profile": profile,
        "evidence": str(evidence),
        "credentials_emitted": False,
    }


def _print_pointer(status: str, evidence: Path, profile: str) -> None:
    print(json.dumps(_pointer(status, evidence, profile), separators=(",", ":"), sort_keys=True))


def _exit_for_status(status: str) -> int:
    return 0 if status == "PASS" else 1 if status == "FAIL" else 2


def main(argv: Sequence[str] | None = None) -> int:
    evidence_path: Path | None = None
    try:
        args = build_parser().parse_args(argv)
        if args.mode == "validate":
            source = _absolute_path(args.input_evidence, "INPUT_EVIDENCE_PATH_INVALID")
            require(source.drive.casefold() == "e:", "INPUT_EVIDENCE_NOT_ON_E_DRIVE")
            payload = _load_json_bytes(
                _bounded_read(source, MAX_EVIDENCE_BYTES, "INPUT_EVIDENCE_INVALID"),
                "INPUT_EVIDENCE_INVALID",
            )
            status = selected_status(payload, args.profile)
            _print_pointer(status, source, args.profile)
            return _exit_for_status(status)

        evidence_path = _evidence_path(args.evidence)
        if args.mode == "dry-run":
            document = dry_run_document()
        else:
            if not args.credentials_stdin:
                raise MissingRuntimeInput("CREDENTIAL_STDIN_NOT_BOUND")
            if args.ack_auth_state_change != ACKNOWLEDGEMENT:
                raise MissingRuntimeInput("AUTH_STATE_CHANGE_APPROVAL_MISSING")
            binding_path = _absolute_path(args.binding, "BINDING_PATH_INVALID")
            binding = load_binding(binding_path)
            credentials = load_credentials_from_stdin()
            document = run_live(binding, credentials)
        validate_evidence_document(document)
        atomic_write_json(evidence_path, document)
        status = str(document["overall_status"])
        _print_pointer(status, evidence_path, "all")
        return _exit_for_status(status)
    except MissingRuntimeInput as exc:
        if evidence_path is None:
            return 2
        document = dry_run_document(exc.code)
        validate_evidence_document(document)
        atomic_write_json(evidence_path, document)
        _print_pointer("UNKNOWN", evidence_path, "all")
        return 2
    except GateError as exc:
        if evidence_path is not None and not evidence_path.exists():
            try:
                document = failure_document(exc.code)
                validate_evidence_document(document)
                atomic_write_json(evidence_path, document)
                _print_pointer("FAIL", evidence_path, "all")
            except GateError:
                pass
        return 1
    except Exception:
        if evidence_path is not None and not evidence_path.exists():
            try:
                document = failure_document("UNEXPECTED_GATE_FAILURE")
                validate_evidence_document(document)
                atomic_write_json(evidence_path, document)
                _print_pointer("FAIL", evidence_path, "all")
            except GateError:
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

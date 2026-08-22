"""Fail-closed client context for the packaged Windows Sandbox qualification route.

The production endpoint policy remains the default.  A loopback endpoint is accepted
only when a package-owned context was created for the current disposable Windows
Sandbox, or while an unfrozen source-only integration test explicitly opts in.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from typing import Mapping
from urllib.parse import urlsplit


CONTRACT_VERSION = "container-audit-isolated-qualification-client-v1"
ACTIVATION_MODE = "windows_sandbox_qualification"
SOURCE_TEST_MODE_ENV = "KMTECH_ISOLATED_QUALIFICATION_SOURCE_TEST_MODE"
STATE_DIRECTORY_NAME = "qualification-authority"
CONTEXT_FILENAME = "client-context.json"
PRODUCER_INGEST_PATH = "/api/producer-ingest/v1/source-file"
MAX_CONTEXT_BYTES = 64 * 1024
EXPECTED_CONTEXT_FIELDS = frozenset(
    {
        "contract_version",
        "activation_mode",
        "authority_instance_id",
        "created_at",
        "machine_name",
        "operator_user_sid",
        "operator_local_app_data_root",
        "state_root",
        "server_base_url",
        "endpoint_url",
        "ca_bundle_path",
    }
)
_AUTHORITY_INSTANCE_RE = re.compile(r"^qualification-[0-9a-f]{32}$")
_WINDOWS_SANDBOX_SID_RE = re.compile(r"^S-1-5-21-(?:[0-9]+-){3}504$")


class IsolatedQualificationError(RuntimeError):
    """Raised when the explicit isolated qualification boundary is not proven."""


@dataclass(frozen=True)
class IsolatedQualificationContext:
    authority_instance_id: str
    machine_name: str
    operator_user_sid: str
    operator_local_app_data_root: str
    state_root: str
    server_base_url: str
    endpoint_url: str
    ca_bundle_path: str
    created_at: str
    source_test_mode: bool = False


def default_state_root(environ: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environ is None else environ
    program_data = str(values.get("PROGRAMDATA") or r"C:\ProgramData").strip()
    return (
        Path(program_data)
        / "KMTech"
        / "DirectSync"
        / "container_audit"
        / STATE_DIRECTORY_NAME
    )


def default_context_path(environ: Mapping[str, str] | None = None) -> Path:
    return default_state_root(environ) / CONTEXT_FILENAME


def _same_path(left: str | os.PathLike[str], right: str | os.PathLike[str]) -> bool:
    return os.path.normcase(os.path.abspath(os.fspath(left))) == os.path.normcase(
        os.path.abspath(os.fspath(right))
    )


def _path_is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, ValueError):
        return False
    return True


def _source_test_mode_allowed(
    state_root: Path,
    environ: Mapping[str, str],
) -> bool:
    if getattr(sys, "frozen", False):
        return False
    if str(environ.get(SOURCE_TEST_MODE_ENV) or "") != "1":
        return False
    try:
        resolved = state_root.resolve(strict=False)
    except OSError:
        return False
    return STATE_DIRECTORY_NAME in {part.lower() for part in resolved.parts}


def assert_windows_sandbox_operator_context(
    *,
    operator_user_sid: str,
    operator_local_app_data_root: str,
    state_root: str | os.PathLike[str],
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Return whether the source-only test escape hatch was used.

    The release path requires the interactive Windows Sandbox account, its RID-504
    SID, its exact profile roots, and the canonical package-owned ProgramData root.
    """

    values = os.environ if environ is None else environ
    root = Path(state_root)
    if _source_test_mode_allowed(root, values):
        return True
    if os.name != "nt":
        raise IsolatedQualificationError("isolated qualification requires Windows")
    if not _same_path(root, default_state_root(values)):
        raise IsolatedQualificationError(
            "isolated qualification state must use the canonical Container_Audit ProgramData root"
        )
    username = str(values.get("USERNAME") or "")
    profile = str(values.get("USERPROFILE") or "")
    local_app_data = str(values.get("LOCALAPPDATA") or "")
    computer_name = str(values.get("COMPUTERNAME") or "").strip()
    if username.casefold() != "wdagutilityaccount":
        raise IsolatedQualificationError(
            "isolated qualification requires the interactive Windows Sandbox account"
        )
    if not computer_name:
        raise IsolatedQualificationError("isolated qualification machine identity is unavailable")
    expected_profile = Path(r"C:\Users\WDAGUtilityAccount")
    expected_local = expected_profile / "AppData" / "Local"
    if not _same_path(profile, expected_profile) or not _same_path(local_app_data, expected_local):
        raise IsolatedQualificationError(
            "isolated qualification requires the canonical Windows Sandbox profile"
        )
    if not _same_path(operator_local_app_data_root, expected_local):
        raise IsolatedQualificationError(
            "captured operator LocalAppData is not the Windows Sandbox profile"
        )
    if not _WINDOWS_SANDBOX_SID_RE.fullmatch(str(operator_user_sid or "")):
        raise IsolatedQualificationError(
            "captured operator SID is not the Windows Sandbox utility account"
        )
    return False


def _assert_bound_submission_endpoint(endpoint_url: str) -> None:
    """Accept an explicitly bound qualification submission endpoint.

    The authority keeps its own loopback endpoint for its bounded duties, so a
    qualification run that binds an external origin must keep submitting there.
    Another loopback origin is still rejected: it would only move the isolated
    route, not leave it.
    """

    parsed = urlsplit(endpoint_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise IsolatedQualificationError(
            "isolated qualification endpoint differs from the requested credential endpoint"
        ) from exc
    hostname = str(parsed.hostname or "").rstrip(".").lower()
    is_loopback = hostname in ("", "localhost") or hostname.endswith(".localhost")
    try:
        is_loopback = is_loopback or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        pass
    if (
        parsed.scheme not in ("http", "https")
        or is_loopback
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path != PRODUCER_INGEST_PATH
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise IsolatedQualificationError(
            "isolated qualification endpoint differs from the requested credential endpoint"
        )


def _load_json_object(path: Path) -> dict:
    try:
        stat = path.stat()
        if stat.st_size <= 0 or stat.st_size > MAX_CONTEXT_BYTES:
            raise IsolatedQualificationError("isolated qualification context size is invalid")
        if path.is_symlink():
            raise IsolatedQualificationError("isolated qualification context must not be a symlink")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except IsolatedQualificationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IsolatedQualificationError(
            f"isolated qualification context is unavailable: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(payload, dict) or set(payload) != EXPECTED_CONTEXT_FIELDS:
        raise IsolatedQualificationError("isolated qualification context fields are invalid")
    return payload


def load_isolated_qualification_context(
    path: str | os.PathLike[str] | None = None,
    *,
    expected_endpoint_url: str = "",
    environ: Mapping[str, str] | None = None,
) -> IsolatedQualificationContext:
    values = os.environ if environ is None else environ
    context_path = Path(path) if path is not None else default_context_path(values)
    payload = _load_json_object(context_path)
    if payload.get("contract_version") != CONTRACT_VERSION:
        raise IsolatedQualificationError("isolated qualification context version is invalid")
    if payload.get("activation_mode") != ACTIVATION_MODE:
        raise IsolatedQualificationError("isolated qualification activation mode is invalid")
    instance_id = str(payload.get("authority_instance_id") or "")
    if not _AUTHORITY_INSTANCE_RE.fullmatch(instance_id):
        raise IsolatedQualificationError("isolated qualification authority identity is invalid")
    state_root = Path(str(payload.get("state_root") or ""))
    source_test_mode = _source_test_mode_allowed(state_root, values)
    if not source_test_mode and not _same_path(state_root, default_state_root(values)):
        raise IsolatedQualificationError("isolated qualification state root is not canonical")
    if not _same_path(context_path, state_root / CONTEXT_FILENAME):
        raise IsolatedQualificationError("isolated qualification context path is not canonical")
    machine_name = str(payload.get("machine_name") or "").strip()
    if not machine_name or machine_name.casefold() != str(
        values.get("COMPUTERNAME") or ""
    ).strip().casefold():
        raise IsolatedQualificationError(
            "isolated qualification context belongs to a different machine"
        )
    if not source_test_mode:
        operator_local = str(payload.get("operator_local_app_data_root") or "")
        operator_sid = str(payload.get("operator_user_sid") or "")
        if not _same_path(
            operator_local, Path(r"C:\Users\WDAGUtilityAccount\AppData\Local")
        ) or not _WINDOWS_SANDBOX_SID_RE.fullmatch(operator_sid):
            raise IsolatedQualificationError(
                "isolated qualification context lacks the Windows Sandbox operator binding"
            )
    server_base_url = str(payload.get("server_base_url") or "")
    endpoint_url = str(payload.get("endpoint_url") or "")
    parsed = urlsplit(server_base_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise IsolatedQualificationError("isolated qualification port is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "127.0.0.1"
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1024 <= port <= 65535
        or server_base_url != f"https://127.0.0.1:{port}"
    ):
        raise IsolatedQualificationError(
            "isolated qualification server must be an exact HTTPS loopback origin"
        )
    expected_endpoint = f"{server_base_url}{PRODUCER_INGEST_PATH}"
    if endpoint_url != expected_endpoint:
        raise IsolatedQualificationError("isolated qualification producer endpoint is invalid")
    requested_endpoint_url = str(expected_endpoint_url or "").strip()
    if requested_endpoint_url and requested_endpoint_url != endpoint_url:
        _assert_bound_submission_endpoint(requested_endpoint_url)
    ca_bundle = Path(str(payload.get("ca_bundle_path") or ""))
    if not _path_is_within(ca_bundle, state_root) or not ca_bundle.is_file():
        raise IsolatedQualificationError("isolated qualification CA bundle is unavailable")
    try:
        ca_size = ca_bundle.stat().st_size
    except OSError as exc:
        raise IsolatedQualificationError("isolated qualification CA bundle cannot be inspected") from exc
    if ca_size <= 0 or ca_size > 128 * 1024 or ca_bundle.is_symlink():
        raise IsolatedQualificationError("isolated qualification CA bundle is invalid")
    return IsolatedQualificationContext(
        authority_instance_id=instance_id,
        machine_name=machine_name,
        operator_user_sid=str(payload.get("operator_user_sid") or ""),
        operator_local_app_data_root=str(
            payload.get("operator_local_app_data_root") or ""
        ),
        state_root=str(state_root.resolve(strict=False)),
        server_base_url=server_base_url,
        endpoint_url=endpoint_url,
        ca_bundle_path=str(ca_bundle.resolve(strict=False)),
        created_at=str(payload.get("created_at") or ""),
        source_test_mode=source_test_mode,
    )


__all__ = [
    "ACTIVATION_MODE",
    "CONTEXT_FILENAME",
    "CONTRACT_VERSION",
    "IsolatedQualificationContext",
    "IsolatedQualificationError",
    "PRODUCER_INGEST_PATH",
    "SOURCE_TEST_MODE_ENV",
    "STATE_DIRECTORY_NAME",
    "assert_windows_sandbox_operator_context",
    "default_context_path",
    "default_state_root",
    "load_isolated_qualification_context",
]

"""Isolated native G: startup admission then an owner generation change."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

source, workspace, scenario, result_path = map(str, sys.argv[1:])
root = Path(workspace)
root.mkdir(parents=True, exist_ok=True)
for name, leaf in (("LOCALAPPDATA", "local"), ("APPDATA", "roaming"),
                   ("PROGRAMDATA", "program"), ("TEMP", "tmp"), ("TMP", "tmp")):
    selected = root / leaf
    selected.mkdir(exist_ok=True)
    os.environ[name] = str(selected)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.path.insert(0, source)

import data_generation_guard as guard
import direct_sync_runtime as runtime
from kmtech_shared import data_generation as generation
from direct_sync_push import DEFAULT_ENDPOINT_PATH
from tools.register_container_audit_worker_pc import _current_user_sid

data = root / "data"
locator_owner = root / "locator"
secret_owner = root / "protected"
tls_owner = root / "tls"
for selected in (data, locator_owner, secret_owner / "secrets", tls_owner):
    selected.mkdir(parents=True, exist_ok=True)
credential = locator_owner / "credential.json"
protected = secret_owner / "secrets" / "credential.dpapi"
ca = tls_owner / "ca.pem"
protected.write_bytes(uuid.uuid4().bytes)
ca.write_bytes(uuid.uuid4().hex.encode("ascii"))
credential.write_text(json.dumps(dict(producer_id=uuid.uuid4().hex,
    key_id=uuid.uuid4().hex, secret_ref="dpapi:credential", secret_data_dir=str(secret_owner),
    endpoint_url="https://qualification.invalid" + DEFAULT_ENDPOINT_PATH, tls_ca_bundle_path=str(ca))), encoding="utf-8")

counts = dict(locator_reads=0, secret_reads=0, tls_reads=0, decryptions=0, requests=0)
original_open = Path.open
read_targets = {credential: "locator_reads", protected: "secret_reads", ca: "tls_reads"}
def open_path(path, *args, **kwargs):
    mode = args[0] if args else kwargs.get("mode", "r")
    if "r" in mode and path in read_targets:
        counts[read_targets[path]] += 1
    return original_open(path, *args, **kwargs)
def decrypt(_):
    counts["decryptions"] += 1
    return uuid.uuid4().hex.encode("ascii")
Path.open = open_path
runtime._dpapi_unprotect_current_user = decrypt

prepared = runtime.prepare_credential_config(credential, data_root=data)
startup_allowed = True
owner = locator_owner if scenario in {"prepared_locator", "raw_locator"} else secret_owner
action = lambda: runtime.load_credentials_from_json(credential, prepared_config=prepared)
if scenario == "raw_locator":
    action = lambda: runtime.load_credentials_from_json(credential, data_root=data)
elif scenario == "prepared_tls":
    owner = tls_owner
elif scenario == "gui_pin_secret":
    import Container_Audit as gui
    app = object.__new__(gui.ContainerAudit)
    app.storage_paths = SimpleNamespace(credential_path=credential, data_root=data)
    app._prepared_admin_pin_credential = prepared
    action = lambda: app._admin_pin_client_for_work()
elif scenario in {"profile_owner", "protected_admin_owner"}:
    owner = root / "profile"
    owner.mkdir()
    profile = owner / "runtime-profile.json"
    profile.write_text("{}", encoding="utf-8")
    guard.probe_before_owner_paths(data, file_paths=(profile,))
    read_targets[profile] = "locator_reads"
    if scenario == "profile_owner":
        from logistics_runtime_profile import load_logistics_runtime_profile
        action = lambda: load_logistics_runtime_profile(True, profile, decryptor=lambda _: decrypt(_).decode())
    else:
        from protected_admin import load_protected_admin_profile
        action = lambda: load_protected_admin_profile(profile)
elif scenario in {"pin_deferred_tls", "runtime_deferred_tls", "transfer_deferred_tls"}:
    owner = tls_owner
    credentials = runtime.load_credentials_from_json(credential, prepared_config=prepared)
    def transport(*args, **kwargs):
        counts["requests"] += 1
        raise AssertionError("native G must precede transport")
    session = SimpleNamespace(post=transport, request=transport)
    if scenario == "pin_deferred_tls":
        from container_admin_pin import AdminPinClient
        client = AdminPinClient(credential, transport=transport, prepared_config=prepared)
        action = lambda: client._post_signed("/api/admin-pin/v1/verifications", {}, response_limit=8192, expected_status=201)
    elif scenario == "runtime_deferred_tls":
        from producer_runtime_client import _post_lease_request
        action = lambda: _post_lease_request(request_value={}, credentials=credentials, session=session, timeout=1)
    else:
        from transfer_client import LogisticsTransferClient
        client = LogisticsTransferClient("https://qualification.invalid", uuid.uuid4().hex,
            uuid.uuid4().hex, session=session, tls_ca_bundle_path=str(ca))
        action = lambda: client._request("GET", "/logistics/api/v1/capabilities")
elif scenario != "allowed":
    assert scenario in {"prepared_locator", "prepared_secret"}

for key in counts:
    counts[key] = 0
if scenario != "allowed":
    release = guard._runtime_release()
    high = "v" + str(int(release["version"].lstrip("vV").split(".")[0]) + 1) + ".0.0"
    generation.record_generation(owner / "data-generation.json", app_id="container_audit",
        subject_sid=_current_user_sid(), version=high, build_id=release["build_id"],
        data_compatible_min_version=high, compatibility_verified=False)

status = "ALLOWED"
try:
    action()
except guard.DataGenerationBlocked as exc:
    status = exc.decision["status"]
except Exception as exc:
    status = "UNEXPECTED:" + type(exc).__name__
result = dict(scenario=scenario, startup_allowed=startup_allowed, status=status, **counts,
              native_g=True, isolated_known_folders=True)
Path(result_path).write_text(json.dumps(result), encoding="utf-8")

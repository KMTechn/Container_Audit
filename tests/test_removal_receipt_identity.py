"""A repeated user removal republishes the SID-bound preservation receipt."""
from contextlib import nullcontext
import json

import current_user_onboarding as onboarding
import data_generation_guard
from tools import register_container_audit_worker_pc as registration


def test_already_removed_user_republishes_sid_bound_receipt(tmp_path, monkeypatch):
    app = tmp_path / "application"
    app.mkdir()
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "worker-data")}
    paths = onboarding.resolve_current_user_onboarding_paths(app, environ=environment)
    paths.data_root.mkdir(parents=True, exist_ok=True)
    original = paths.data_root / "preserved.bin"
    original.write_bytes(b"preserved-business-data")
    monkeypatch.setattr(data_generation_guard, "_authenticated_support_removal_source", lambda *args: nullcontext())
    monkeypatch.setattr(data_generation_guard, "probe_before_owner_paths", lambda *args, **kwargs: None)
    monkeypatch.setattr(registration, "_current_user_sid", lambda: "fixture-worker")
    options = dict(environ=environment, autostart_remover=lambda: {"status": "ABSENT"},
                   relay_stopper=lambda *args: {"status": "ABSENT"})
    first = onboarding.remove_current_user_setup(app, **options)
    assert first["status"] == "PASS_DATA_PRESERVED"
    assert first.get("operator_sid") == "fixture-worker"
    paths.removal_report_path.unlink()
    second = onboarding.remove_current_user_setup(app, **options)
    saved = json.loads(paths.removal_report_path.read_text(encoding="utf-8-sig"))
    assert saved["operator_sid"] == second["operator_sid"] == first["operator_sid"]
    assert saved["status"] == "PASS_DATA_PRESERVED"
    assert second["report_version"] == first["report_version"]
    assert original.read_bytes() == b"preserved-business-data"

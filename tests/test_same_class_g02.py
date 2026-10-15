"""G02: native task readback preserves account and XML boolean meaning."""
from types import SimpleNamespace
import json
import subprocess
import xml.etree.ElementTree as ET

import pytest

import auto_update as update


@pytest.mark.parametrize("readback", ("system-name", "system-alias", "hidden-one", "terminate-zero"))
def test_owned_task_accepts_equivalent_native_readback(tmp_path, monkeypatch, readback):
    sid = "S-1-5-21-1-2-3-1001"
    task = ET.fromstring(update.logon_task_xml(app_root=tmp_path, operator_sid=sid))
    path, value = {
        "system-name": ("{*}Principals/{*}Principal/{*}UserId", "SYSTEM"),
        "system-alias": ("{*}Principals/{*}Principal/{*}UserId", r"NT AUTHORITY\SYSTEM"),
        "hidden-one": ("{*}Settings/{*}Hidden", "1"),
        "terminate-zero": ("{*}Settings/{*}AllowHardTerminate", "0"),
    }[readback]
    task.find(path).text = value
    observed = ET.tostring(task, encoding="unicode")
    calls = []

    def observe(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=observed, stderr="")

    monkeypatch.setattr(subprocess, "run", observe)
    accepted = update.supported_task_present(tmp_path, sid)
    (tmp_path / "same-class-g02-observation.json").write_text(
        json.dumps({"readback": readback, "accepted": accepted, "reader_calls": len(calls)}),
        encoding="utf-8",
    )
    assert len(calls) == 1, "the real task reader must consume scheduler output"
    assert accepted, "equivalent owned task readback must remain reusable"

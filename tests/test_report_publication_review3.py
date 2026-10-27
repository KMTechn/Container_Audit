import json
from pathlib import Path
import subprocess

import pytest
import report_publication as publication


@pytest.mark.parametrize("writer", ["_write_json_atomic", "_write_json_atomic_create_new"])
def test_ready_fallback_passes_installer_command_readback(tmp_path, writer):
    import current_user_onboarding as onboarding
    command = '"C:\\portable\\python.exe" -I "C:\\portable\\app\\relay.py"'
    target = tmp_path / "current_user_onboarding.json"
    payload = {"status": "READY", "relay_autostart": {"command": command}, "message": "synthetic-collision"}
    getattr(onboarding, writer).__wrapped__(target, payload,
        environ={"KMTECH_TEST_API_TOKEN": "synthetic-collision"})
    assert json.loads(target.read_text(encoding="utf-8"))["relay_autostart"]["command"] == command
    # Execute the installer's exact readback comparison with a synthetic Snapshot.
    source = (Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1").read_text(encoding="utf-8-sig")
    begin = source.index("$onboarding = Get-Content $onboardingPath -Raw -Encoding UTF8 | ConvertFrom-Json")
    end = source.index("throw 'Onboarding Run readback failed.'", begin)
    end = source.index("}", end) + 1
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps({"path": str(target), "wanted": command}), encoding="utf-8")
    script = tmp_path / "readback.ps1"
    prefix = "param($fixture)\nImport-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Management'))\nImport-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Utility'))\n$f=Get-Content -LiteralPath $fixture -Raw | ConvertFrom-Json\n$onboardingPath=$f.path\n$wanted=$f.wanted\nfunction Set-InstallationEvidenceStage($value) {}\nfunction Snapshot { return @{exists=$true;data=$wanted} }\n"
    script.write_text(prefix + source[begin:end], encoding="utf-8-sig")
    result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), str(fixture)],
        capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0


@pytest.mark.parametrize("status", ["DRY_RUN", "APPLYING", "APPLY_REQUESTED"])
def test_install_pack_fallback_keeps_in_progress_status(tmp_path, monkeypatch, status):
    import auto_update
    from tools import direct_sync_relay_install_pack as pack
    def refused(value):
        raise ValueError("REPORT_UNAVAILABLE")
    monkeypatch.setattr(auto_update, "serialize_json_for_sink", refused)
    target = tmp_path / "report.json"
    assert pack._write_json(target, {"status": status, "message": "synthetic-diagnostic"})
    assert json.loads(target.read_text(encoding="utf-8"))["status"] == status


def test_failed_publication_is_not_counted(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding
    import atomic_replace
    target = tmp_path / "current_user_onboarding.json"
    def refused(*args):
        raise OSError("synthetic-publish-failure")
    monkeypatch.setattr(atomic_replace, "atomic_replace", refused)
    with pytest.raises(OSError):
        onboarding._write_json_atomic.__wrapped__(target, {"status": "READY", "message": "synthetic-collision"},
            environ={"KMTECH_TEST_API_TOKEN": "synthetic-collision"})
    assert publication.failure_count(target) == 0
    assert not (tmp_path / ".report-unavailable-count.json").exists()


def test_publication_adds_to_persisted_counter(tmp_path):
    import current_user_onboarding as onboarding
    counter = tmp_path / ".report-unavailable-count.json"
    counter.write_text('{"count":7}', encoding="utf-8")
    for expected in (8, 9):
        onboarding._write_json_atomic.__wrapped__(tmp_path / "current_user_onboarding.json",
            {"status": "READY", "message": "synthetic-collision"},
            environ={"KMTECH_TEST_API_TOKEN": "synthetic-collision"})
        assert json.loads(counter.read_text(encoding="utf-8"))["count"] == expected


def test_counter_accumulates_across_fresh_processes(tmp_path):
    from pathlib import Path
    import subprocess
    import sys
    counter = tmp_path / ".report-unavailable-count.json"
    counter.write_text('{"count":7}', encoding="utf-8")
    child = tmp_path / "publish_child.py"
    child.write_text("""import json, os, sys, uuid
from pathlib import Path
repo, directory = map(Path, sys.argv[1:])
sys.path[:0] = ['E:/KMTech/shared-tools/prodblock', str(repo)]
import sitecustomize
import report_publication as publication
def refused(value):
    raise ValueError('REPORT_UNAVAILABLE')
def writer(path, value):
    temporary = path.with_name(uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value), encoding='utf-8')
    os.replace(temporary, path)
prepared = publication.prepare_report({}, render=refused, fallback_render=json.dumps,
    unavailable_codes=('REPORT_UNAVAILABLE',))
target = directory / 'diagnostic.json'
target.write_text(prepared.text, encoding='utf-8')
publication.record_publication(prepared, path=target, writer=writer)
""", encoding="utf-8")
    for expected in (8, 9):
        result = subprocess.run([sys.executable, "-I", "-B", str(child),
            str(Path(__file__).resolve().parents[1]), str(tmp_path)], capture_output=True,
            timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0
        assert json.loads(counter.read_text(encoding="utf-8"))["count"] == expected


def test_concurrent_publications_add_to_existing_counter(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import os
    import uuid
    counter = tmp_path / ".report-unavailable-count.json"
    counter.write_text('{"count":7}', encoding="utf-8")
    def writer(path, value):
        temporary = path.with_name(uuid.uuid4().hex + ".tmp")
        temporary.write_text(json.dumps(value), encoding="utf-8")
        os.replace(temporary, path)
    def publish_one(index):
        target = tmp_path / (str(index) + ".json")
        prepared = publication.PreparedReport('{"message":"보고 못 씀"}', True)
        target.write_text(prepared.text, encoding="utf-8")
        publication.record_publication(prepared, path=target, writer=writer)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(publish_one, (1, 2)))
    assert json.loads(counter.read_text(encoding="utf-8"))["count"] == 9

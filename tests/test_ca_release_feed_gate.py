"""Exercise the production entry and preserve its approved bytes in a fixture ZIP."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from tests.release_feed_fixture import canonical_release_settings, CANONICAL_SHA256
from tools import build_portable_release_candidate as builder

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("entry", ("cli", "api"))
@pytest.mark.parametrize("case", ("omitted", "empty_object", "empty_feed", "wrong_sha"))
def test_operating_release_entry_rejects_bad_feed_before_output(tmp_path, monkeypatch, entry, case):
    approved = canonical_release_settings(tmp_path)
    original_input = approved.read_bytes()
    path = tmp_path / "bad-settings.json"
    if case == "empty_object":
        path.write_text("{}", encoding="utf-8")
    elif case == "empty_feed":
        value = json.loads(approved.read_bytes())
        value["feed_url"] = ""
        path.write_text(json.dumps(value), encoding="utf-8")
    elif case == "wrong_sha":
        # Same parsed settings; only the approved input's exact bytes differ.
        path.write_bytes(approved.read_bytes() + b"\n")
    else:
        path = None
    output = tmp_path / "packet"

    def unexpected(*args, **kwargs):
        raise AssertionError("settings refusal must precede source/build/output work")

    monkeypatch.setattr(builder, "_assert_clean_source", unexpected)
    if entry == "cli":
        args = ["--output", str(output), "--repo-root", str(ROOT)]
        if path is not None:
            args += ["--auto-update-settings", str(path)]
        with pytest.raises(SystemExit if path is None else builder.PortableBuildError):
            builder.main(args)
    else:
        with pytest.raises(builder.PortableBuildError):
            builder.build(ROOT, tmp_path / "runtime-source", output, auto_update_settings=path)
    assert not output.exists()
    assert approved.read_bytes() == original_input


def test_canonical_cli_packet_and_fixture_zip_keep_input_bytes(tmp_path, monkeypatch, capsys):
    approved = canonical_release_settings(tmp_path)
    raw = approved.read_bytes()

    def runtime(_source, target):
        target.mkdir(parents=True)
        (target / "python.exe").write_bytes(b"fixture runtime")
        (target / "pythonw.exe").write_bytes(b"fixture runtime")

    def application(_source, target):
        target.mkdir(parents=True)
        (target / "Container_Audit.py").write_bytes((ROOT / "Container_Audit.py").read_bytes())
        return []

    actual_run = builder.subprocess.run

    def shared_check(command, *args, **kwargs):
        if any(Path(str(item)).name == "check_kmtech_shared.py" for item in command):
            return SimpleNamespace(returncode=0, stderr="")
        return actual_run(command, *args, **kwargs)

    # Only assembly dependencies are doubles. main -> build -> input admission,
    # settings publication/readback, manifest assembly and the ZIP bytes are real.
    monkeypatch.setattr(builder, "_assert_clean_source", lambda root: None)
    monkeypatch.setattr(builder, "_assert_writer_sink_inventory", lambda root: {"inventory_sha256": "1" * 64})
    monkeypatch.setattr(builder, "_runtime_source", runtime)
    monkeypatch.setattr(builder, "_copy_application", application)
    monkeypatch.setattr(builder, "_assert_screen_bundle", lambda *args: {})
    monkeypatch.setattr(builder, "_copy_third_party", lambda *args: {})
    monkeypatch.setattr(builder, "_assert_portable_import_closure", lambda *args: None)
    monkeypatch.setattr(builder, "_app_native_inventory", lambda *args: [])
    monkeypatch.setattr(builder, "_assert_installer_unsigned_pins", lambda *args: None)
    monkeypatch.setattr(builder, "_build_environment", lambda *args: {"fixture": True})
    monkeypatch.setattr(builder.subprocess, "run", shared_check)
    output = tmp_path / "packet"
    assert builder.main(["--output", str(output), "--repo-root", str(ROOT),
                         "--auto-update-settings", str(approved)]) == 0
    capsys.readouterr()
    installed = output / "app/auto-update-settings.json"
    assert installed.read_bytes() == raw
    archive = tmp_path / "fixture-packet.zip"
    with ZipFile(archive, "w") as zip_file:
        for path in output.rglob("*"):
            if path.is_file():
                zip_file.write(path, path.relative_to(output).as_posix())
    with ZipFile(archive) as zip_file:
        packed = zip_file.read("app/auto-update-settings.json")
    assert packed == raw
    assert hashlib.sha256(packed).hexdigest() == CANONICAL_SHA256
    assert json.loads(packed)["approved_transitions"] == []


def test_settings_publication_readback_failure_is_fatal(tmp_path, monkeypatch):
    approved = canonical_release_settings(tmp_path)
    target = tmp_path / "app"
    target.mkdir()
    original = Path.write_bytes

    def corrupt(path, data):
        return original(path, data + b"\n")

    monkeypatch.setattr(Path, "write_bytes", corrupt)
    with pytest.raises(builder.PortableBuildError, match="^RELEASE_AUTO_UPDATE_SETTINGS_READBACK_FAILED$"):
        builder._write_release_auto_update_settings(target, approved.read_bytes())

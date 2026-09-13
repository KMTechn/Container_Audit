"""Explicit regressions for pinned verdicts and advisory checkout failures."""
from contextlib import nullcontext
import json
import shutil
import subprocess

import pytest

from tests.integration import check_kmtech_shared_canonical as integration


@pytest.fixture
def copied_checkouts(tmp_path, monkeypatch, capsys):
    local = integration.local
    source = local.ROOT
    app = tmp_path / "app"
    shutil.copytree(source / "kmtech_shared", app / "kmtech_shared",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("kmtech_shared.manifest.json", "kmtech_shared.lock.json"):
        shutil.copyfile(source / name, app / name)
    canonical = tmp_path / "kmtech_shared"
    canonical.mkdir()
    git_dir = subprocess.run(
        ["git", "-C", str(source.parent / "kmtech_shared"), "rev-parse", "--absolute-git-dir"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    # Only read-only Git queries use the original object store; edits stay here.
    (canonical / ".git").write_text(f"gitdir: {git_dir}\n", encoding="utf-8")
    shutil.copytree(app / "kmtech_shared", canonical / "kmtech_shared")
    monkeypatch.setattr(local, "ROOT", app)
    monkeypatch.setattr(capsys, "disabled", nullcontext)
    return app, canonical, source


def test_current_checkout_syntax_error_is_advisory(copied_checkouts, tmp_path, capsys):
    app, canonical, source = copied_checkouts
    shutil.copytree(source.parent / "kmtech_shared/kmtech_shared", canonical / "kmtech_shared",
                    dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))
    initializer = canonical / "kmtech_shared/__init__.py"
    initializer.write_bytes(initializer.read_bytes() + b"\ndef unfinished_edit(\n")

    integration.test_canonical_shared_source_matches_app_checker(tmp_path, capsys)

    output = capsys.readouterr().out
    assert "PASS shared 0.2.0" in output
    notices = [line for line in output.splitlines() if line.startswith("정본 현재 파일 확인 불가:")]
    assert len(notices) == 1
    assert "SyntaxError" in notices[0]


def test_current_checkout_git_failure_is_advisory(copied_checkouts, tmp_path, monkeypatch, capsys):
    app, canonical, source = copied_checkouts
    initializer = canonical / "kmtech_shared/__init__.py"
    initializer.write_bytes(initializer.read_bytes() + b"\n# current checkout drift\n")
    run = subprocess.run

    def failed_head(command, **kwargs):
        if command[-2:] == ["rev-parse", "HEAD"]:
            result = subprocess.CompletedProcess(command, 128, "", "synthetic HEAD lookup failure\n")
            if kwargs.get("check"):
                result.check_returncode()
            return result
        return run(command, **kwargs)

    monkeypatch.setattr(integration.subprocess, "run", failed_head)
    integration.test_canonical_shared_source_matches_app_checker(tmp_path, capsys)

    output = capsys.readouterr().out
    assert "PASS shared 0.2.0" in output
    notices = [line for line in output.splitlines() if line.startswith("정본 현재 파일 확인 불가:")]
    assert len(notices) == 1
    assert "CalledProcessError" in notices[0]


def test_pinned_byte_mismatch_still_fails(copied_checkouts, tmp_path, capsys):
    app, canonical, source = copied_checkouts
    local = integration.local
    path = app / "kmtech_shared/runtime.py"
    path.write_bytes(path.read_bytes() + b"\n# app-only mutation\n")
    manifest_path = app / "kmtech_shared.manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"]["kmtech_shared/runtime.py"] = local.digest(path.read_bytes())
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    lock_path = app / "kmtech_shared.lock.json"
    lock = json.loads(lock_path.read_bytes())
    lock["manifest_sha256"] = local.digest(manifest_path.read_bytes())
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    (canonical / "kmtech_shared/__init__.py").write_text("def unfinished_edit(\n", encoding="utf-8")
    assert local.main(["--check"]) == 0

    with pytest.raises(AssertionError, match="kmtech_shared/runtime.py"):
        integration.test_canonical_shared_source_matches_app_checker(tmp_path, capsys)

    assert "정본 현재 파일 확인 불가:" not in capsys.readouterr().out


def test_standalone_checker_needs_no_canonical_checkout(tmp_path):
    source = integration.local.ROOT
    app = tmp_path / "app"
    shutil.copytree(source / "kmtech_shared", app / "kmtech_shared",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("kmtech_shared.manifest.json", "kmtech_shared.lock.json", "qualification/check_kmtech_shared.py"):
        target = app / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    assert not (app.parent / "kmtech_shared").exists()

    result = subprocess.run(
        [integration.sys.executable, "-I", "-B", str(app / "qualification/check_kmtech_shared.py"), "--check"],
        cwd=app, capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS shared 0.2.0" in result.stdout

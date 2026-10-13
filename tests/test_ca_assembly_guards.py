import ast
import json
import os
from pathlib import Path

import pytest

import auto_update
import user_relay


def test_install_server_origin_change_survives_public_support_record(capsys):
    code = "INSTALL_SERVER_ORIGIN_CHANGED"
    auto_update.emit_support_record(
        {"status": "RECOVERY_REQUIRED", "reason_code": code, "error_code": code},
        stage="onboarding",
    )
    output = capsys.readouterr().out
    record = json.loads(output[output.index("{"):])
    assert record["status"] == "RECOVERY_REQUIRED"
    assert record["reason_code"] == code
    assert record["error_code"] == code


@pytest.mark.parametrize("separate_argument", [False, True])
def test_tracker_counts_shell_webview_and_excludes_foreign_udf(
    tmp_path, monkeypatch, separate_argument,
):
    # Exercise the actual path helper without importing the Tk application.
    app_dir = Path(__file__).resolve().parents[1]
    source = ast.parse((app_dir / "ca_screen_bridge.py").read_text(encoding="utf-8"))
    helper = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                  and node.name == "shell_data_dir")
    namespace = {"Path": Path, "os": os, "APP_DIR": app_dir}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), "ca_screen_bridge.py", "exec"), namespace)
    shell_data_dir = namespace["shell_data_dir"]

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    data_root = tmp_path / "custom-data"
    shell_udf = shell_data_dir() / "webview2"
    legacy_udf = data_root / "webview2"

    def browser(pid, udf=None, parent_pid=0):
        command = "browser"
        if udf is not None:
            separator = " " if separate_argument else "="
            command += ' --user-data-dir' + separator + '"' + str(udf) + '"'
        return {
            "pid": pid, "name": "msedgewebview2.exe", "image": "browser.exe",
            "command": command, "parent_pid": parent_pid,
            "created_at": "2026-10-13T10:00:00+00:00", "session_id": 1,
        }

    tracker = user_relay.AppProcessTracker(tmp_path / "current" / "app", data_root, own_pid=99)
    shell = browser(42, shell_udf)
    child = browser(43, parent_pid=42)
    foreign = browser(44, tmp_path / "other-app" / "webview2", parent_pid=42)
    legacy = browser(45, legacy_udf)
    sibling = browser(46, str(shell_udf) + "-other", parent_pid=42)
    assert {row["pid"] for row in tracker.observe([shell, child, foreign, legacy, sibling])} == {42, 43, 45}
    # Orphaned shell children remain attributed after the Python/browser parent exits.
    assert [row["pid"] for row in tracker.observe([child, foreign, sibling])] == [43]

import pytest

import user_relay


def row(pid, name="pythonw.exe", image=r"E:\installed\runtime\pythonw.exe", **kwargs):
    return dict(pid=pid, name=name, image=image, command="", parent_pid=0,
                created_at="2026-10-13T00:00:00+00:00", session_id=1, **kwargs)


def test_stop_relay_absence_does_not_prove_app_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    monkeypatch.setattr(user_relay, "native_app_process_snapshot", lambda: [row(41)], raising=False)
    result = user_relay.request_app_stop(tmp_path, app_root=r"E:\installed\app",
                                         data_root=tmp_path, timeout_seconds=0)
    assert result["status"] == "UNKNOWN"
    assert result["remaining_processes"] == [{"pid": 41, "name": "pythonw.exe"}]


def test_stop_waits_for_owned_webview_after_python_exits(tmp_path, monkeypatch):
    browser = row(42, "msedgewebview2.exe", r"C:\webview\msedgewebview2.exe")
    browser.update(parent_pid=41, command='browser --user-data-dir="E:\\state\\webview2"',
                   created_at="2026-10-13T00:00:01+00:00")
    child = row(43, "msedgewebview2.exe", r"C:\webview\msedgewebview2.exe")
    child.update(parent_pid=42, created_at="2026-10-13T00:00:02+00:00")
    snapshots = iter([[row(41), browser, child], [browser, child], [child], []])
    monkeypatch.setattr(user_relay, "native_app_process_snapshot", lambda: next(snapshots), raising=False)
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    waited = []
    result = user_relay.request_app_stop(tmp_path, app_root=r"E:\installed\app",
        data_root=r"E:\state", timeout_seconds=1, wait=waited.append)
    assert result["status"] == "STOPPED"
    assert result["remaining_processes"] == []
    assert len(waited) == 2


def test_tracker_excludes_other_profiles_and_pid_reuse():
    tracker = user_relay.AppProcessTracker(r"E:\installed\app", r"E:\state", own_pid=99)
    foreign = row(44, "msedgewebview2.exe", r"C:\webview\msedgewebview2.exe")
    foreign.update(command='browser --user-data-dir="E:\\state-other\\webview2"', parent_pid=42,
                   created_at="2026-10-13T00:00:01+00:00")
    browser = {**foreign, "pid": 42, "command": 'browser --user-data-dir="e:/STATE/webview2"'}
    child = {**foreign, "pid": 43, "command": "", "parent_pid": 42,
             "created_at": "2026-10-13T00:00:01+00:00"}
    assert {r["pid"] for r in tracker.observe([browser, child, foreign])} == {42, 43}
    reused = {**child, "created_at": "2026-10-13T00:01:00+00:00"}
    assert tracker.observe([reused, foreign]) == []


@pytest.mark.parametrize("bad_parent", ["created_at", "session_id"])
def test_tracker_requires_live_compatible_parent(bad_parent):
    tracker = user_relay.AppProcessTracker(r"E:\installed\app", r"E:\state", own_pid=99)
    parent = row(41)
    child = row(43, "msedgewebview2.exe", r"C:\webview\msedgewebview2.exe")
    child["parent_pid"] = 41
    child[bad_parent] = "2026-10-12T00:00:00+00:00" if bad_parent == "created_at" else 2
    assert [r["pid"] for r in tracker.observe([parent, child])] == [41]


def test_stop_unknown_observation_fails_closed(tmp_path, monkeypatch):
    def unavailable():
        raise OSError("observation unavailable")
    monkeypatch.setattr(user_relay, "native_app_process_snapshot", unavailable, raising=False)
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    result = user_relay.request_app_stop(tmp_path, timeout_seconds=0)
    assert result["status"] == "UNKNOWN"


def test_cli_exit_code_requires_whole_tree_absence(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(user_relay, "request_app_stop", lambda *a, **k: {
        "status": "UNKNOWN", "relay": {"status": "ABSENT"},
        "remaining_processes": [{"pid": 41, "name": "pythonw.exe"}],
    })
    assert user_relay.main(["--data-root", str(tmp_path), "--direct-sync-root",
                            str(tmp_path / "relay"), "--request-app-stop"]) == 1


def test_stop_has_one_150_second_budget_for_relay_and_tree(tmp_path, monkeypatch):
    elapsed = [0.0]
    monkeypatch.setattr(user_relay.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "UNKNOWN"})
    monkeypatch.setattr(user_relay, "acquire_runtime_instance", lambda *a: None)
    monkeypatch.setattr(user_relay, "native_app_process_snapshot", lambda: [row(41)])
    def wait(seconds):
        elapsed[0] += seconds
    result = user_relay.request_app_stop(tmp_path, app_root=r"E:\installed\app", wait=wait)
    assert result["status"] == "UNKNOWN"
    assert result["remaining_count"] == 1
    assert elapsed[0] == 150.0


def test_failed_initial_observation_cannot_lose_orphan_evidence(tmp_path, monkeypatch):
    observations = iter([None, []])
    def snapshot():
        rows = next(observations)
        if rows is None:
            raise OSError("observation unavailable")
        return rows
    monkeypatch.setattr(user_relay, "native_app_process_snapshot", snapshot)
    monkeypatch.setattr(user_relay, "request_user_relay_stop", lambda *a, **k: {"status": "ABSENT"})
    result = user_relay.request_app_stop(tmp_path, timeout_seconds=0)
    assert result["status"] == "UNKNOWN"
    assert result["observation_status"] == "UNKNOWN"


@pytest.mark.parametrize("option", ['--user-data-dir="E:\\state folder\\webview2"',
                                   '--user-data-dir "e:/STATE folder/webview2"'])
def test_webview_ownership_parses_windows_arguments(option):
    tracker = user_relay.AppProcessTracker(r"E:\installed\app", r"E:\state folder", own_pid=99)
    browser = row(42, "msedgewebview2.exe", r"C:\webview\msedgewebview2.exe")
    browser["command"] = "browser " + option
    assert [r["pid"] for r in tracker.observe([browser])] == [42]


@pytest.mark.parametrize("entry", [r"E:\installed\current\app",
                                  "E:\\installed\\versions\\" + "a" * 40 + "\\app"])
def test_stop_includes_version_runtimes_only_in_the_same_installation(entry):
    tracker = user_relay.AppProcessTracker(entry, r"E:\state", own_pid=99)
    rows = [row(41, image=r"E:\installed\current\runtime\pythonw.exe"),
            row(42, image="E:\\installed\\versions\\" + "b" * 40 + "\\runtime\\python.exe"),
            row(43, image="E:\\installed-other\\versions\\" + "b" * 40 + "\\runtime\\pythonw.exe"),
            row(44, image=r"E:\installed\versions\unverified\runtime\pythonw.exe")]
    assert [r["pid"] for r in tracker.observe(rows)] == [41, 42]

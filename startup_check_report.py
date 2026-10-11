"""Best-effort non-authoritative startup result; never add a launch refusal."""
from contextvars import ContextVar
import json
import os
from pathlib import Path
import uuid

from startup_check import REASON_CATEGORIES, startup_result
from writer_session_fence import _assert_no_reparse_components, writer_sink

NOTICE = "이 PC 는 지금 새 프로그램을 열 수 없습니다. 관리자에게 알렸습니다. 다른 작업대로 옮겨 주세요."
_STATE = ContextVar("container_start_check_report", default=None)


def begin(version, *, enabled=True):
    _STATE.set(None)
    if not enabled:
        return
    category = os.environ.get("KMTECH_START_CHECK_TEST_CATEGORY", "")
    state = {"version": version, "build_sha": "", "reasons": [], "revision": 0,
             "published": -1, "forced": category if "TEST_" + category in REASON_CATEGORIES else ""}
    _STATE.set(state)


def note(reason):
    state = _STATE.get()
    if state is not None and reason not in state["reasons"]:
        state["reasons"].append(reason)
        state["revision"] += 1


def release_identity(release):
    state = _STATE.get()
    if state is not None:
        identity = (release.get("version", state["version"]), release.get("build_id", ""))
        if identity != (state["version"], state["build_sha"]):
            state["version"], state["build_sha"] = identity
            state["revision"] += 1


def publish(reason=None, *, refused=False):
    state = _STATE.get()
    if state is None:
        return False
    try:
        if reason:
            note(reason)
        if state["published"] != state["revision"]:
            reasons = ["TEST_" + state["forced"]] if state["forced"] else state["reasons"]
            result = startup_result(state["version"], state["build_sha"], reasons)
            state["published"] = state["revision"]
            _write_result(result)
        return bool(refused)
    except Exception:
        return False


def finish(reason=None, *, refused=False, failed=False):
    try:
        state = _STATE.get()
        if failed and state is not None and not any(
                REASON_CATEGORIES.get(item, "UNKNOWN") != "ALREADY_RUNNING" for item in state["reasons"]):
            note("UNKNOWN_CHECK")
        return publish(reason, refused=refused)
    finally:
        _STATE.set(None)


def observe(action, *args, **kwargs):
    try:
        if action == "begin":
            return begin(*args, **kwargs)
        if action == "note":
            return note(*args, **kwargs)
        if action == "release_identity":
            return release_identity(*args, **kwargs)
        if action == "publish":
            return publish(*args, **kwargs)
        if action == "finish":
            return finish(*args, **kwargs)
        raise ValueError("unknown report observation")
    except Exception:
        state = _STATE.get()
        if state is None and action == "begin" and kwargs.get("enabled", True):
            _STATE.set({"version": "", "build_sha": "", "reasons": [], "revision": 0,
                        "published": -1, "forced": ""})
        note("UNKNOWN_CHECK")
        return False


@writer_sink("startup_check_report", report_only=True)
def _write_result(result):
    temporary = None
    try:
        program_data = Path(os.environ["PROGRAMDATA"])
        if not program_data.is_absolute():
            return
        folder = program_data / "KMTech/start-check"
        if not folder.is_dir():
            return
        _assert_no_reparse_components(folder)
        # Rebuild the public envelope: discard any unapproved raw fields.
        result = startup_result(result["version"], result["build_sha"], result["reasons"])
        destination = folder / (result["checked_at"][:10].replace("-", "") + "-CA.json")
        _assert_no_reparse_components(destination)
        temporary = folder / ("." + destination.name + "." + uuid.uuid4().hex + ".tmp")
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n")
        os.replace(temporary, destination)
    except Exception:
        pass
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

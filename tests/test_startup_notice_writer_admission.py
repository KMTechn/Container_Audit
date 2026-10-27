"""A second launch must leave the running GUI free to save scans."""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from queue import Queue
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import runtime_instance
import writer_session_fence as fence


def _try_other_thread_admission(control_root):
    results = Queue()

    def save_scan():
        try:
            with fence.writer_admission(
                "gui_tray_state_save", control_root=control_root, timeout_seconds=0,
            ):
                results.put("admitted")
        except fence.WriterFenceError as exc:
            results.put(exc.code)

    worker = threading.Thread(target=save_scan)
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "zero-timeout admission did not finish"
    return results.get_nowait()


def test_notice_probe_uses_the_same_real_mutex():
    control_root = fence.canonical_control_root()
    with fence.writer_admission("gui_startup", control_root=control_root):
        assert _try_other_thread_admission(control_root) == "WRITER_GATE_TIMEOUT"
    assert _try_other_thread_admission(control_root) == "admitted"


@pytest.mark.parametrize("branch,kind,title,body", [
    (
        "lock-error", "showerror", "이적을 시작하지 못했습니다",
        "이 PC에서 이적 프로그램을 안전하게 시작하지 못했습니다 — 다시 켜 보고, 또 나오면 현장 관리자에게 알리세요",
    ),
    (
        "duplicate", "showwarning", "프로그램이 이미 실행 중입니다",
        "같은 PC에서 이적 검사 프로그램을 두 번 실행할 수 없습니다. "
        "열려 있는 창을 사용해 주세요.",
    ),
    (
        "shutdown-stall", "showwarning", "프로그램이 이미 실행 중입니다",
        "이전 프로그램의 종료 정리가 아직 끝나지 않았습니다. "
        "잠시 기다린 뒤 다시 실행하세요. 앱이 닫히고 다시 안 켜지면 PC를 재시작하세요.",
    ),
], ids=["lock-error", "duplicate", "shutdown-stall"])
def test_startup_notice_releases_writer_before_waiting(
    tmp_path, monkeypatch, branch, kind, title, body,
):
    data_root = tmp_path / "data"
    data_root.mkdir()
    control_root = fence.canonical_control_root()
    preparation = []
    notices = []
    admissions = []
    startup_acquisitions = []
    startup_thread = threading.current_thread()
    acquire_mutex = fence._acquire_named_mutex

    def counted_mutex(*args, **kwargs):
        if threading.current_thread() is startup_thread:
            startup_acquisitions.append(True)
        return acquire_mutex(*args, **kwargs)

    monkeypatch.setattr(fence, "_acquire_named_mutex", counted_mutex)
    monkeypatch.setattr(ca, "verify_factory_contract_startup",
                        lambda: preparation.append("contract"))
    monkeypatch.setattr(ca, "probe_before_owner_paths",
                        lambda *_args, **_kwargs: preparation.append("probe"))
    monkeypatch.setattr(ca, "validate_existing_data_root",
                        lambda _root: preparation.append("validate"))

    def acquire(root):
        assert root == data_root
        preparation.append("instance")
        if branch == "lock-error":
            raise OSError("synthetic instance-lock failure")
        return None

    def stalled(root):
        assert root == data_root
        preparation.append("stall")
        return branch == "shutdown-stall"

    def notice(selected_kind):
        def show(actual_title, actual_body):
            notices.append((selected_kind, actual_title, actual_body))
            admissions.append(_try_other_thread_admission(control_root))
        return show

    def unexpected_start(*_args, **_kwargs):
        pytest.fail("a refused launch continued startup")

    monkeypatch.setattr(ca, "acquire_runtime_instance", acquire)
    monkeypatch.setattr(ca, "shutdown_stall_is_live", stalled)
    for selected_kind in ("showerror", "showwarning"):
        monkeypatch.setattr(ca.messagebox, selected_kind, notice(selected_kind))
    monkeypatch.setattr(ca, "_show_visible_startup_notice", notice("showerror"))
    monkeypatch.setattr(ca, "_show_startup_notice", notice("showerror"))
    for name in ("clear_shutdown_stall", "_first_run_onboarding_enabled",
                 "record_before_owner_paths", "prepare_startup_item_catalog", "ContainerAudit"):
        monkeypatch.setattr(ca, name, unexpected_start)

    assert ca._prepare_gui_startup(data_root=data_root) is None
    assert notices == [(kind, title, body)]
    # O1: a refused instance never enters contract, generation or access probes.
    assert preparation == ["instance"] + (
        [] if branch == "lock-error" else ["stall"]
    )
    assert admissions == ["admitted"]
    assert startup_acquisitions == [True]  # The existing decorator performs one short probe.


def _running_scan_process(data_root):
    """Exercise the product save sink and kernel lease in a separate process."""
    root = Path(data_root)
    lease = runtime_instance.acquire_runtime_instance(root)
    assert lease is not None
    app = SimpleNamespace(save_folder=str(root), CURRENT_TRAY_STATE_FILE="tray.json",
                          _stage_checkpoint_audit_events=lambda _state: None)
    totals = {"saved": 0, "rejected": 0}
    try:
        while not (root / "stop").exists():
            try:
                saved = ca.ContainerAudit._save_tray_state_snapshot(
                    app, {"scan": totals["saved"] + 1},
                )
                assert saved, "product tray persistence failed"
                totals["saved"] += 1
            except fence.WriterFenceError as exc:
                assert exc.code == "WRITER_GATE_TIMEOUT"
                totals["rejected"] += 1
            # Observation must remain available even when the product gate denies a scan.
            (root / "progress.json").write_text(json.dumps(totals), encoding="utf-8")
            time.sleep(0.02)
    finally:
        lease.release()
    print(json.dumps(totals))


def _wait_progress(root, predicate, process=None):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            totals = json.loads((root / "progress.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            totals = {}
        if predicate(totals):
            return totals
        if process is not None and process.poll() is not None:
            pytest.fail(f"running scan process exited with code {process.returncode}")
        time.sleep(0.02)
    pytest.fail("running scan process did not reach its synchronization point")


def test_duplicate_start_only_probes_writer_while_first_process_saves(
    tmp_path, monkeypatch,
):
    import current_user_onboarding as onboarding

    data_root = tmp_path / "data"
    data_root.mkdir()
    command = [sys.executable, "-B", "-c",
               "from tests.test_startup_notice_writer_admission import _running_scan_process; "
               "import sys; _running_scan_process(sys.argv[1])", str(data_root)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    counts = {"admission": 0, "body_admission": 0, "verify": 0, "contract": 0, "generation": 0}
    holds = []
    notices = []
    acquire_mutex = fence._acquire_named_mutex
    body_admission = ca.writer_admission
    in_body = False

    @contextmanager
    def counted_body_admission(*args, **kwargs):
        nonlocal in_body
        counts["body_admission"] += 1
        in_body = True
        try:
            with body_admission(*args, **kwargs):
                yield
        finally:
            in_body = False

    def counted_mutex(*args, **kwargs):
        lease = acquire_mutex(*args, **kwargs)
        if lease is not None:
            counts["admission"] += 1
            started = time.perf_counter_ns()
            kind = "body" if in_body else "probe"
            release = lease.release

            def measured_release():
                release()
                holds.append({"kind": kind, "hold_ns": time.perf_counter_ns() - started})

            lease.release = measured_release
        return lease

    def slow_integrity(*_args, **_kwargs):
        counts["verify"] += 1
        # Model the measured HDD integrity work inside the real admission.
        _wait_progress(data_root, lambda value: value.get("rejected", 0) > 0)
        return {"status": "PASS"}

    def generation(*_args, **_kwargs):
        counts["generation"] += 1
        onboarding.verify_bootstrap_integrity(None)

    def show(title, body):
        assert getattr(fence._WRITER_LOCAL, "depth", 0) == 0
        notices.append((title, body))
        before = _wait_progress(data_root, lambda value: value.get("saved", 0) >= 3)
        _wait_progress(data_root, lambda value: value.get("saved", 0) >= before["saved"] + 3)

    try:
        _wait_progress(data_root, lambda value: value.get("saved", 0) >= 3, process)
        # Do not replace either instance acquisition or writer admission.
        assert runtime_instance.acquire_runtime_instance(data_root) is None
        monkeypatch.setattr(fence, "_acquire_named_mutex", counted_mutex)
        monkeypatch.setattr(ca, "writer_admission", counted_body_admission)
        monkeypatch.setattr(onboarding, "verify_bootstrap_integrity", slow_integrity)
        monkeypatch.setattr(ca, "verify_factory_contract_startup",
                            lambda: counts.__setitem__("contract", counts["contract"] + 1))
        monkeypatch.setattr(ca, "probe_before_owner_paths", generation)
        monkeypatch.setattr(ca, "validate_existing_data_root", lambda _root: None)
        monkeypatch.setattr(ca.messagebox, "showwarning", show)
        monkeypatch.setattr(ca, "ContainerAudit", lambda: pytest.fail("duplicate constructed GUI"))
        assert ca._prepare_gui_startup(data_root=data_root) is None
    finally:
        (data_root / "stop").touch()
        stdout, stderr = process.communicate(timeout=30)
        evidence_root = os.environ.get("KMTECH_TEST_CA_TASK_ROOT")
        if evidence_root:
            (Path(evidence_root) / "scan-process.json").write_text(
                json.dumps(dict(returncode=process.returncode, stdout=stdout, stderr=stderr),
                           ensure_ascii=False, indent=2), encoding="utf-8",
            )
    assert process.returncode == 0, stderr
    totals = json.loads(stdout)
    evidence = dict(second=counts, holds=holds, first=totals, notices=notices,
                    persisted=json.loads((data_root / "tray.json").read_text(encoding="utf-8")))
    evidence_root = os.environ.get("KMTECH_TEST_CA_TASK_ROOT")
    if evidence_root:
        (Path(evidence_root) / "second-launch-scan.json").write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8",
        )
    assert counts == {"admission": 1, "body_admission": 0, "verify": 0, "contract": 0, "generation": 0}, evidence
    assert len(holds) == 1 and holds[0]["kind"] == "probe" and holds[0]["hold_ns"] > 0, evidence
    assert totals["saved"] >= 6 and totals["rejected"] == 0, evidence
    assert evidence["persisted"]["scan"] == totals["saved"]
    assert notices == [("프로그램이 이미 실행 중입니다",
                        "같은 PC에서 이적 검사 프로그램을 두 번 실행할 수 없습니다. "
                        "열려 있는 창을 사용해 주세요.")]


@pytest.mark.parametrize("phase", ["contract", "probe", "credential", "validate", "missing-root"])
def test_owned_instance_is_released_on_admitted_preparation_failure(tmp_path, monkeypatch, phase):
    data_root = tmp_path / "data"
    if phase != "missing-root":
        data_root.mkdir()
    paths = ca.build_container_audit_storage_paths(data_root=data_root)
    if phase == "credential":
        paths.credential_path.parent.mkdir(parents=True, exist_ok=True)
        paths.credential_path.touch()
        import direct_sync_runtime

        def reject_credential(*_args, **_kwargs):
            raise OSError("synthetic credential preparation failure")
        monkeypatch.setattr(direct_sync_runtime, "prepare_credential_config", reject_credential)

    def reject(*_args, **_kwargs):
        assert getattr(fence._WRITER_LOCAL, "depth", 0) > 0
        raise OSError("synthetic admitted preparation failure")

    for name, selected in (("verify_factory_contract_startup", "contract"),
                           ("probe_before_owner_paths", "probe"),
                           ("validate_existing_data_root", "validate")):
        monkeypatch.setattr(ca, name, reject if selected == phase else lambda *_args, **_kwargs: None)
    # Contract errors propagate; path/credential failures retain the existing translation.
    failure_type = OSError if phase == "contract" else ca.DataRootUnavailableError
    with pytest.raises(failure_type):
        ca._prepare_gui_startup(data_root=data_root)
    lease = runtime_instance.acquire_runtime_instance(data_root)
    assert lease is not None, "failed preparation retained the instance lease"
    lease.release()


def test_first_start_keeps_preparation_order_and_retains_instance(tmp_path, monkeypatch):
    data_root = tmp_path / "data"
    data_root.mkdir()
    calls = []
    acquire = ca.acquire_runtime_instance

    def instance(root):
        assert getattr(fence._WRITER_LOCAL, "depth", 0) == 0
        calls.append("instance")
        return acquire(root)

    def step(name, admitted=True):
        def record(*_args, **_kwargs):
            if admitted:
                assert getattr(fence._WRITER_LOCAL, "depth", 0) > 0
            calls.append(name)
        return record

    app = SimpleNamespace(root=SimpleNamespace(after=lambda *_args: None))
    monkeypatch.setattr(ca, "acquire_runtime_instance", instance)
    monkeypatch.setattr(ca, "verify_factory_contract_startup", step("contract"))
    monkeypatch.setattr(ca, "probe_before_owner_paths", step("probe"))
    monkeypatch.setattr(ca, "validate_existing_data_root", step("validate"))
    monkeypatch.setattr(ca, "clear_shutdown_stall", step("clear", False))
    monkeypatch.setattr(ca, "_first_run_onboarding_enabled", lambda: False)
    monkeypatch.setattr(ca, "record_before_owner_paths", step("record", False))
    monkeypatch.setattr(ca, "prepare_startup_item_catalog", step("catalog", False))
    monkeypatch.setattr(ca, "ContainerAudit", lambda: (step("gui")() or app))
    result = ca._prepare_gui_startup(data_root=data_root)
    try:
        assert result[0] is app
        assert calls == ["instance", "contract", "probe", "validate", "clear", "record", "catalog", "gui"]
        assert runtime_instance.acquire_runtime_instance(data_root) is None
    finally:
        result[1].release()


def test_instance_is_released_when_real_writer_admission_is_denied(tmp_path, monkeypatch):
    data_root = tmp_path / "data"
    data_root.mkdir()
    ready, held, release = threading.Event(), threading.Event(), threading.Event()
    acquire = ca.acquire_runtime_instance
    acquired = []

    def instance(root):
        lease = acquire(root)
        assert lease is not None
        acquired.append(True)
        ready.set()
        assert held.wait(5)
        return lease

    def deployment():
        assert ready.wait(30)
        with fence.writer_admission("gui_startup"):
            held.set()
            assert release.wait(30)

    worker = threading.Thread(target=deployment)
    worker.start()
    try:
        monkeypatch.setattr(ca, "acquire_runtime_instance", instance)
        monkeypatch.setattr(ca, "writer_admission", lambda source:
                            fence.writer_admission(source, timeout_seconds=0))
        with pytest.raises(fence.WriterFenceError) as caught:
            ca._prepare_gui_startup(data_root=data_root)
        assert caught.value.code == "WRITER_GATE_TIMEOUT"
        assert acquired == [True]
        lease = runtime_instance.acquire_runtime_instance(data_root)
        assert lease is not None, "denied admission retained the instance lease"
        lease.release()
    finally:
        ready.set()
        release.set()
        worker.join(5)
        assert not worker.is_alive()

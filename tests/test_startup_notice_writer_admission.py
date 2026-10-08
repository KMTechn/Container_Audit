"""A second launch must leave the running GUI free to save scans."""
import threading
from queue import Queue

import pytest

import Container_Audit as ca
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
        "lock-error", "showerror", "프로그램 실행 잠금 실패",
        "데이터 충돌 방지를 위한 실행 잠금을 확인하지 못했습니다. "
        "프로그램을 시작하지 않고 관리자에게 문의합니다.",
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
    for name in ("clear_shutdown_stall", "_first_run_onboarding_enabled",
                 "record_before_owner_paths", "prepare_startup_item_catalog", "ContainerAudit"):
        monkeypatch.setattr(ca, name, unexpected_start)

    assert ca._prepare_gui_startup(data_root=data_root) is None
    assert notices == [(kind, title, body)]
    assert preparation == ["contract", "probe", "validate", "instance"] + (
        [] if branch == "lock-error" else ["stall"]
    )
    assert admissions == ["admitted"]

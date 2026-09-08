from types import SimpleNamespace

import pytest

import Container_Audit as container_module
from Container_Audit import ContainerAudit, TraySession
from tests.operation_lease_fixtures import fixed_operation_lease_clock
from tests.test_terminal_operation_lease import _rejected_review
from transfer_seal import TransferSealError
from warning_presenter import WarningPresenter

pytestmark = pytest.mark.usefixtures("fixed_operation_lease_clock")


class RecordingLane:
    def __init__(self):
        self.tasks = []

    def is_busy(self):
        return bool(self.tasks)

    def submit(self, task):
        self.tasks.append(task)
        return SimpleNamespace(accepted=True)


def _review_ui(tmp_path, monkeypatch, *, role="ADMIN", confirm=True, audit_ok=True):
    coordinator, manager, intent_id, posted, _db_path = _rejected_review(tmp_path)
    lane = RecordingLane()
    audit = []
    messages = []
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = SimpleNamespace()
    app.worker_name = "review-supervisor"
    app.worker_role = role
    app._scan_callback_epoch = 2
    app.current_tray = TraySession()
    app.warning_presenter = WarningPresenter()
    app._transfer_post_review_cases = tuple(dict(row) for row in coordinator.store.post_review_cases(active_only=True))
    app._ui_task_lane = lambda: lane
    app._transfer_seal_runtime = lambda: coordinator
    app._update_action_button_states = lambda: None
    app._refresh_transfer_post_review_state = lambda: True
    app._log_event = lambda event, **kwargs: audit.append((event, kwargs)) or audit_ok
    monkeypatch.setattr(container_module.messagebox, "askyesno", lambda *_args, **_kwargs: confirm)
    monkeypatch.setattr(container_module.messagebox, "showwarning", lambda *args, **_kwargs: messages.append(args))
    monkeypatch.setattr(container_module.messagebox, "showinfo", lambda *args, **_kwargs: messages.append(args))
    return app, lane, audit, posted, coordinator, intent_id, messages


def test_normal_supervisor_action_audits_before_same_command_retry(tmp_path, monkeypatch):
    app, lane, audit, posted, coordinator, intent_id, messages = _review_ui(tmp_path, monkeypatch)
    assert app._retry_transfer_post_review() is True
    assert len(posted) == 1 and audit == []
    task = lane.tasks[0]
    result = task.work()
    task.finish(result)
    assert result.status == "ACKED"
    assert len(posted) == 2 and posted[0]["json"] == posted[1]["json"]
    assert audit[0][0] == "TRANSFER_SEAL_REVIEW_RETRY_REQUESTED"
    assert audit[0][1]["synchronous"] is True
    assert audit[0][1]["worker_name_override"] == "review-supervisor"
    assert audit[0][1]["detail"]["transfer_intent_id"] == intent_id
    assert messages[-1][0] == "중앙 반영 확인"


@pytest.mark.parametrize("blocked", ["worker", "cancelled", "active_tray", "worker_changed", "audit_failed"])
def test_review_action_rejects_unauthorized_or_unsafe_ui_boundary(tmp_path, monkeypatch, blocked):
    app, lane, audit, posted, coordinator, intent_id, _messages = _review_ui(
        tmp_path, monkeypatch, role="WORKER" if blocked == "worker" else "ADMIN",
        confirm=blocked != "cancelled", audit_ok=blocked != "audit_failed",
    )
    if blocked == "active_tray":
        app.current_tray.master_label_code = "active-other-tray"
    if blocked in {"worker", "cancelled", "active_tray"}:
        assert app._retry_transfer_post_review() is False
        assert lane.tasks == []
    else:
        assert app._retry_transfer_post_review() is True
        if blocked == "worker_changed":
            app.worker_role = "WORKER"
            app.worker_name = "other-worker"
        with pytest.raises(TransferSealError):
            lane.tasks[0].work()
    assert coordinator.store.load(intent_id)["status"] == "OPERATOR_REVIEW"
    assert len(posted) == 1

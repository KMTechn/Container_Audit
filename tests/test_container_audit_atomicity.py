import csv
import datetime
import json
from pathlib import Path

import pytest

import Container_Audit as container_audit_module
import tray_state
from Container_Audit import ContainerAudit, TraySession


class _Toggle:
    def __init__(self) -> None:
        self.value = False

    def set(self, value) -> None:
        self.value = value


def _activation_app(tmp_path: Path) -> ContainerAudit:
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = "atomic-worker"
    app.worker_role = "WORKER"
    app.save_folder = str(tmp_path)
    app.log_file_path = str(tmp_path / "events.csv")
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.current_tray = TraySession()
    app._pending_activation_event_contract = None
    app._pending_completion_event_contract = None
    app._pending_operator_review_snapshot = None
    app._tray_state_persist_lock = container_audit_module.threading.RLock()
    app.is_idle = False
    app.last_activity_time = None
    app.log_write_errors = []
    app.last_log_write_error = None
    app.show_tray_image_var = _Toggle()
    app.COLOR_DANGER = "danger"
    app._clear_settled_operator_context = lambda: None
    app._update_tray_image_display = lambda: None
    app._update_current_item_label = lambda: None
    app._update_center_display = lambda: None
    app._start_stopwatch = lambda: None
    app._invalidate_pending_scan_callbacks = lambda: None
    app.show_status_message = lambda *args, **kwargs: None
    app.show_worker_input_screen = lambda: None
    return app


def _csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as f_handle:
        return list(csv.DictReader(f_handle))


@pytest.mark.parametrize(
    ("event_type", "master_label", "detail"),
    [
        (
            "MASTER_LABEL_SCANNED_NEW",
            '{"CLC":"AAA2270730100","QT":"60"}',
            {"CLC": "AAA2270730100", "QT": "60"},
        ),
        (
            "MASTER_LABEL_SCANNED_OLD",
            "AAA2270730100",
            {"master_label_code": "AAA2270730100"},
        ),
    ],
)
def test_master_activation_atomically_stages_and_projects_exact_event_once(
    tmp_path,
    event_type,
    master_label,
    detail,
):
    app = _activation_app(tmp_path)

    assert app._activate_master_label_tray(
        barcode=master_label,
        item_code="AAA2270730100",
        tray_quantity=60,
        matched_item={"Item Name": "fixture", "Spec": "fixture"},
        event_name=event_type,
        event_detail=detail,
    ) is True

    state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert tray_state.ACTIVATION_EVENT_STATE_KEY not in state
    rows = _csv_rows(tmp_path / "events.csv")
    activation_rows = [row for row in rows if row["event"] == event_type]
    assert len(activation_rows) == 1
    projected_detail = json.loads(activation_rows[0]["details"])
    assert projected_detail["idempotency_key"].startswith("tray-activation:")
    assert activation_rows[0]["timestamp"] == app.current_tray.start_time.isoformat()
    assert activation_rows[0]["worker_name"] == "atomic-worker"


def test_pre_event_cut_preserves_full_outbox_and_restart_projects_it(
    tmp_path,
    monkeypatch,
):
    crash_child = _activation_app(tmp_path)
    crash_child._project_activation_event_contract = lambda _contract: False
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showerror",
        lambda *args, **kwargs: None,
    )

    assert crash_child._activate_master_label_tray(
        barcode="AAA2270730100",
        item_code="AAA2270730100",
        tray_quantity=60,
        matched_item={"Item Name": "fixture", "Spec": "fixture"},
        event_name="MASTER_LABEL_SCANNED_OLD",
        event_detail={"master_label_code": "AAA2270730100"},
    ) is False

    state_path = tmp_path / "current.json"
    after_cut = json.loads(state_path.read_text(encoding="utf-8"))
    contract = after_cut[tray_state.ACTIVATION_EVENT_STATE_KEY]
    assert contract["event_type"] == "MASTER_LABEL_SCANNED_OLD"
    assert contract["master_label_code"] == "AAA2270730100"
    assert contract["projection_worker_name"] == "atomic-worker"
    assert contract["projection_log_name"] == "events.csv"
    assert contract["event_detail"] == {"master_label_code": "AAA2270730100"}
    assert _csv_rows(tmp_path / "events.csv") == []

    restarted = _activation_app(tmp_path)
    assert restarted._reconcile_activation_event_from_state(after_cut) is True

    repaired = json.loads(state_path.read_text(encoding="utf-8"))
    assert tray_state.ACTIVATION_EVENT_STATE_KEY not in repaired
    rows = _csv_rows(tmp_path / "events.csv")
    assert [row["event"] for row in rows] == ["MASTER_LABEL_SCANNED_OLD"]
    projected_detail = json.loads(rows[0]["details"])
    assert projected_detail["idempotency_key"] == contract["idempotency_key"]
    assert rows[0]["timestamp"] == contract["observed_at"]


def test_load_current_tray_state_reconciles_activation_before_restore_event(
    tmp_path,
    monkeypatch,
):
    crash_child = _activation_app(tmp_path)
    crash_child._project_activation_event_contract = lambda _contract: False
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showerror",
        lambda *args, **kwargs: None,
    )
    assert crash_child._activate_master_label_tray(
        barcode="AAA2270730100",
        item_code="AAA2270730100",
        tray_quantity=60,
        matched_item={"Item Name": "fixture", "Spec": "fixture"},
        event_name="MASTER_LABEL_SCANNED_OLD",
        event_detail={"master_label_code": "AAA2270730100"},
    ) is False

    restarted = _activation_app(tmp_path)
    restarted.completed_master_labels = set()
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesnocancel",
        lambda *args, **kwargs: True,
    )
    restarted._load_current_tray_state()

    rows = _csv_rows(tmp_path / "events.csv")
    assert [row["event"] for row in rows] == [
        "MASTER_LABEL_SCANNED_OLD",
        "TRAY_RESTORE",
    ]
    assert restarted.current_tray.master_label_code == "AAA2270730100"
    assert tray_state.ACTIVATION_EVENT_STATE_KEY not in json.loads(
        (tmp_path / "current.json").read_text(encoding="utf-8")
    )


def test_append_ack_loss_restart_deduplicates_before_clearing_outbox(
    tmp_path,
    monkeypatch,
):
    staging = _activation_app(tmp_path)
    staging._project_activation_event_contract = lambda _contract: False
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showerror",
        lambda *args, **kwargs: None,
    )
    assert staging._activate_master_label_tray(
        barcode="AAA2270730100",
        item_code="AAA2270730100",
        tray_quantity=60,
        matched_item={"Item Name": "fixture", "Spec": "fixture"},
        event_name="MASTER_LABEL_SCANNED_OLD",
        event_detail={"master_label_code": "AAA2270730100"},
    ) is False

    state_path = tmp_path / "current.json"
    pending = json.loads(state_path.read_text(encoding="utf-8"))
    contract = pending[tray_state.ACTIVATION_EVENT_STATE_KEY]
    original_append = container_audit_module.append_event_log_entry_idempotent

    def append_then_lose_ack(*args, **kwargs):
        original_append(*args, **kwargs)
        raise OSError("simulated acknowledgement loss after durable append")

    monkeypatch.setattr(
        container_audit_module,
        "append_event_log_entry_idempotent",
        append_then_lose_ack,
    )
    first_restart = _activation_app(tmp_path)
    assert first_restart._reconcile_activation_event_from_state(pending) is False
    assert len(_csv_rows(tmp_path / "events.csv")) == 1
    assert tray_state.ACTIVATION_EVENT_STATE_KEY in json.loads(
        state_path.read_text(encoding="utf-8")
    )

    monkeypatch.setattr(
        container_audit_module,
        "append_event_log_entry_idempotent",
        original_append,
    )
    second_restart = _activation_app(tmp_path)
    pending_again = json.loads(state_path.read_text(encoding="utf-8"))
    assert second_restart._reconcile_activation_event_from_state(pending_again) is True

    rows = _csv_rows(tmp_path / "events.csv")
    assert len(rows) == 1
    assert json.loads(rows[0]["details"])["idempotency_key"] == contract[
        "idempotency_key"
    ]
    assert tray_state.ACTIVATION_EVENT_STATE_KEY not in json.loads(
        state_path.read_text(encoding="utf-8")
    )


def test_activation_outbox_validation_rejects_state_identity_mismatch(tmp_path):
    app = _activation_app(tmp_path)
    tray = TraySession(
        master_label_code="AAA2270730100",
        item_code="AAA2270730100",
        item_name="fixture",
        item_spec="fixture",
        tray_size=60,
        start_time=datetime.datetime.now(),
    )
    state = tray_state.tray_session_to_state(tray, worker_name=app.worker_name)
    contract = app._activation_event_contract(
        event_type="MASTER_LABEL_SCANNED_OLD",
        event_detail={"master_label_code": "AAA2270730100"},
        master_label_code="AAA2270730100",
        observed_at=tray.start_time,
    )
    state[tray_state.ACTIVATION_EVENT_STATE_KEY] = contract
    assert tray_state.validate_tray_state(state, default_tray_size=60) is state

    state["master_label_code"] = "DIFFERENT"
    with pytest.raises(
        tray_state.TrayStateValidationError,
        match="master_label_code does not match tray state",
    ):
        tray_state.validate_tray_state(state, default_tray_size=60)

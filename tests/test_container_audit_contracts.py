import base64
import csv
import datetime
import hashlib
import json
from pathlib import Path
import queue

import pytest

import Container_Audit as container_audit_module
import event_contracts
import event_log_store
import event_payloads
import item_catalog
import label_qr
import parked_tray_store
import product_exchange
import replacement_log_lookup
import session_history
import storage_utils
import tray_state
import worker_registry
from Container_Audit import ContainerAudit, ProductExchangeSession, TraySession, WorkerRegistry


def _headless_app():
    return ContainerAudit.__new__(ContainerAudit)


def test_normalize_app_settings_rejects_non_object_root():
    assert container_audit_module.normalize_app_settings(["not", "an", "object"]) == {}


def test_normalize_app_settings_clamps_numeric_scale_and_drops_malformed_values():
    settings = container_audit_module.normalize_app_settings(
        {
            "scale_factor": 99,
            "column_widths_validator": {
                "summary_item": 180,
                "bad_text": "wide",
                "bad_bool": True,
                123: 240,
            },
            "paned_window_sash_positions": {
                "0": 320,
                "1": -1,
                "2": False,
            },
            "enable_internal_test_commands": "true",
        }
    )

    assert settings == {
        "scale_factor": 2.5,
        "column_widths_validator": {"summary_item": 180},
        "paned_window_sash_positions": {"0": 320},
    }
    assert container_audit_module.normalize_app_settings({"scale_factor": -1})["scale_factor"] == 0.7
    assert "scale_factor" not in container_audit_module.normalize_app_settings({"scale_factor": True})
    assert container_audit_module.normalize_app_settings({"enable_internal_test_commands": False}) == {
        "enable_internal_test_commands": False
    }


def test_load_app_settings_returns_normalized_settings_from_file(tmp_path):
    app = _headless_app()
    app.config_folder = str(tmp_path)
    app.SETTINGS_FILE = "settings.json"
    (tmp_path / "settings.json").write_text(
        json.dumps(
            {
                "scale_factor": "bad",
                "column_widths_validator": {"item": 120},
                "paned_window_sash_positions": [],
                "enable_internal_test_commands": True,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    assert app.load_app_settings() == {
        "column_widths_validator": {"item": 120},
        "enable_internal_test_commands": True,
    }


def test_release_runtime_drops_internal_test_commands_on_load_and_save(tmp_path, monkeypatch):
    app = _headless_app()
    app.config_folder = str(tmp_path)
    app.SETTINGS_FILE = "settings.json"
    app.scale_factor = 1.0
    app.column_widths = {}
    app.paned_window_sash_positions = {}
    app.internal_test_commands_enabled = True
    (tmp_path / "settings.json").write_text(
        json.dumps(
            {
                "scale_factor": 1.0,
                "enable_internal_test_commands": True,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(container_audit_module.sys, "frozen", True, raising=False)

    loaded = app.load_app_settings()
    app.save_settings()

    saved = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert loaded == {"scale_factor": 1.0}
    assert "enable_internal_test_commands" not in saved


class DummyListbox:
    def __init__(self):
        self.deleted = False

    def delete(self, *args):
        self.deleted = True


class CapturingListbox:
    def __init__(self):
        self.rows = []
        self.configs = []

    def insert(self, index, value):
        if index == 0:
            self.rows.insert(0, value)
        else:
            self.rows.append(value)

    def delete(self, index):
        if self.rows:
            del self.rows[index]

    def itemconfig(self, index, config):
        self.configs.append((index, config))

    def winfo_exists(self):
        return True

    def size(self):
        return len(self.rows)

    def get(self, index):
        return self.rows[index]


class CapturingLayoutParent:
    def __init__(self, width, height):
        self.width = width
        self.height = height

    def winfo_width(self):
        return self.width

    def winfo_height(self):
        return self.height


class CapturingLayoutListbox:
    def __init__(self, parent, height):
        self.master = parent
        self.height = height
        self.configure_calls = []
        self.grid_calls = []

    def winfo_exists(self):
        return True

    def winfo_height(self):
        return self.height

    def configure(self, **kwargs):
        self.configure_calls.append(kwargs)

    def grid_configure(self, **kwargs):
        self.grid_calls.append(kwargs)


class CapturingTree:
    def __init__(self):
        self.rows = {}

    def get_children(self):
        return list(self.rows)

    def delete(self, iid):
        self.rows.pop(iid, None)

    def insert(self, _parent, _index, *, values, iid):
        self.rows[iid] = values


def test_scanned_listbox_metrics_expand_roomy_center_and_compact_low_screen():
    app = _headless_app()
    app.scale_factor = 1.0

    compact = app._get_scanned_listbox_metrics(center_width=360, center_height=520, list_height=160)
    roomy = app._get_scanned_listbox_metrics(center_width=900, center_height=900, list_height=440)

    assert roomy["font_size"] >= 18
    assert roomy["font_size"] >= compact["font_size"]
    assert compact["visible_rows"] >= 5
    assert compact["top_pady"] <= 14
    assert roomy["horizontal_pad"] > compact["horizontal_pad"]


def test_scanned_listbox_metrics_honor_user_scale_with_clamps():
    app = _headless_app()
    app.scale_factor = 2.5

    metrics = app._get_scanned_listbox_metrics(center_width=320, center_height=500, list_height=150)

    assert metrics["font_size"] >= 35
    assert metrics["visible_rows"] >= 5
    assert metrics["top_pady"] <= 35


def test_apply_scanned_listbox_layout_configures_widget_and_caches_metrics():
    app = _headless_app()
    app.scale_factor = 1.0
    app._scanned_listbox_layout_job = "pending"
    app._scanned_listbox_layout_metrics = None
    parent = CapturingLayoutParent(width=860, height=880)
    app.scanned_listbox = CapturingLayoutListbox(parent=parent, height=420)

    app._apply_scanned_listbox_layout()

    assert app._scanned_listbox_layout_job is None
    first_config = app.scanned_listbox.configure_calls[-1]
    assert first_config["font"][0] == app.DEFAULT_FONT
    assert first_config["font"][1] >= 18
    assert first_config["height"] >= 8
    first_grid = app.scanned_listbox.grid_calls[-1]
    assert first_grid["padx"] >= 12
    assert first_grid["pady"][0] <= 28

    app._apply_scanned_listbox_layout()

    assert len(app.scanned_listbox.configure_calls) == 1
    assert len(app.scanned_listbox.grid_calls) == 1


def test_pane_layout_metrics_cap_sidebars_on_wide_monitors():
    app = _headless_app()
    app.scale_factor = 1.0

    standard = app._get_pane_layout_metrics(1366)
    wide = app._get_pane_layout_metrics(2560)

    assert wide["left_width"] <= 380
    assert wide["right_width"] <= 360
    assert wide["center_width"] > standard["center_width"]
    assert wide["center_width"] == 2560 - wide["left_width"] - wide["right_width"]


def test_center_layout_metrics_use_vertical_space_without_overgrowing_low_screens():
    app = _headless_app()
    app.scale_factor = 1.0

    low = app._get_center_layout_metrics(center_width=720, center_height=560)
    tall = app._get_center_layout_metrics(center_width=1100, center_height=960)

    assert tall["list_minsize"] > low["list_minsize"]
    assert tall["count_font"] >= low["count_font"]
    assert low["button_top"] <= 14
    assert tall["horizontal_pad"] > low["horizontal_pad"]


def test_right_sidebar_metrics_stretch_cards_on_tall_screens():
    app = _headless_app()
    app.scale_factor = 1.0

    short = app._get_right_sidebar_layout_metrics(620)
    tall = app._get_right_sidebar_layout_metrics(1080)

    assert tall["card_minsize"] > short["card_minsize"]
    assert tall["card_gap"] >= short["card_gap"]
    assert short["card_minsize"] >= 78


class DummyToggle:
    def __init__(self):
        self.value = None

    def set(self, value):
        self.value = value


class DummyButton:
    def __init__(self):
        self.config_calls = []
        self.options = {}

    def config(self, **kwargs):
        self.options.update(kwargs)
        self.config_calls.append(kwargs)

    def configure(self, **kwargs):
        self.config(**kwargs)

    def cget(self, key):
        return self.options.get(key)

    def __getitem__(self, key):
        return self.options.get(key)

    def __setitem__(self, key, value):
        self.options[key] = value


class DummyIntVar:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


class RaisingIntVar:
    def get(self):
        raise container_audit_module.tk.TclError("expected integer")


def test_action_button_states_follow_tray_scans_and_modal_modes():
    app = _headless_app()
    app.current_tray = TraySession()
    app.master_label_replace_state = None
    app.reset_button = DummyButton()
    app.park_button = DummyButton()
    app.undo_button = DummyButton()
    app.submit_tray_button = DummyButton()
    app.replace_master_label_button = DummyButton()
    app.exchange_button = DummyButton()

    app._update_action_button_states()

    assert app.reset_button["state"] == container_audit_module.tk.DISABLED
    assert app.park_button["state"] == container_audit_module.tk.DISABLED
    assert app.undo_button["state"] == container_audit_module.tk.DISABLED
    assert app.submit_tray_button["state"] == container_audit_module.tk.DISABLED
    assert app.replace_master_label_button["state"] == container_audit_module.tk.NORMAL
    assert app.exchange_button["state"] == container_audit_module.tk.NORMAL

    app.current_tray = TraySession(master_label_code="ACTIVE")
    app._update_action_button_states()

    assert app.reset_button["state"] == container_audit_module.tk.NORMAL
    assert app.park_button["state"] == container_audit_module.tk.NORMAL
    assert app.undo_button["state"] == container_audit_module.tk.DISABLED
    assert app.submit_tray_button["state"] == container_audit_module.tk.DISABLED
    assert app.replace_master_label_button["state"] == container_audit_module.tk.DISABLED
    assert app.exchange_button["state"] == container_audit_module.tk.DISABLED

    app.current_tray.scanned_barcodes.append("AAA2270730100-001")
    app._update_action_button_states()

    assert app.undo_button["state"] == container_audit_module.tk.NORMAL
    assert app.submit_tray_button["state"] == container_audit_module.tk.NORMAL

    app.current_tray = TraySession()
    app.master_label_replace_state = "awaiting_old_completed"
    app._update_action_button_states()

    assert app.replace_master_label_button["text"] == "교체 취소"
    assert app.replace_master_label_button["style"] == "Danger.TButton"
    assert app.replace_master_label_button["state"] == container_audit_module.tk.NORMAL
    assert app.exchange_button["state"] == container_audit_module.tk.DISABLED


def test_action_button_states_treat_open_exchange_dialog_as_existing_flow():
    app = _headless_app()
    app.current_tray = TraySession()
    app.master_label_replace_state = None
    app.replace_master_label_button = DummyButton()
    app.exchange_button = DummyButton()
    app.exchange_dialog = type("DummyDialog", (), {"winfo_exists": lambda self: True})()

    app._update_action_button_states()

    assert app.replace_master_label_button["state"] == container_audit_module.tk.DISABLED
    assert app.exchange_button["state"] == container_audit_module.tk.NORMAL
    assert app.exchange_button["text"] == "교환 창 보기"


class DummyRoot:
    def after(self, _delay, _callback, *args):
        return "after-id"

    def after_cancel(self, _job):
        return None

    def winfo_exists(self):
        return True


class CapturingRoot:
    def __init__(self):
        self.calls = []

    def after(self, _delay, callback, *args):
        self.calls.append((callback, args))
        return "after-id"


class ClockRoot:
    def __init__(self):
        self.cancelled = []

    def after_cancel(self, job):
        self.cancelled.append(job)


class DummyScanEntry:
    def __init__(self, value):
        self.value = value
        self.deleted = False

    def get(self):
        return self.value

    def delete(self, *_args):
        self.deleted = True


class FakeDownloadResponse:
    def __init__(self, chunks, headers=None):
        self._chunks = chunks
        self.headers = headers or {}

    def iter_content(self, chunk_size):
        return iter(self._chunks)


def _completion_app(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.log_file_path = str(tmp_path / "events.csv")
    app.log_queue = queue.Queue()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1", "BC-2"],
        scan_times=[
            datetime.datetime(2026, 6, 22, 9, 1, 0),
            datetime.datetime(2026, 6, 22, 9, 2, 0),
        ],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=1.5,
        stopwatch_seconds=120.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
        has_error_or_reset=True,
    )
    app.completed_master_labels = set()
    app.work_summary = {}
    app.total_tray_count = 0
    app.completed_tray_times = []
    app.tray_last_end_time = None
    app.scanned_listbox = DummyListbox()
    app.undo_button = {"state": "normal"}
    app.COLOR_DANGER = "danger"
    app.COLOR_SUCCESS = "success"
    app.COLOR_PRIMARY = "primary"
    app.messages = []
    app.stopwatch_stopped = False
    app.idle_stopped = False
    app.state_deleted = False
    app.summaries_updated = False
    app.ui_reset = False
    app._stop_stopwatch = lambda: setattr(app, "stopwatch_stopped", True)
    app._stop_idle_checker = lambda: setattr(app, "idle_stopped", True)
    app._delete_current_tray_state = lambda: setattr(app, "state_deleted", True)
    app._update_all_summaries = lambda: setattr(app, "summaries_updated", True)
    app._reset_ui_to_waiting_state = lambda: setattr(app, "ui_reset", True)
    app._update_best_time_records = lambda work_time: None
    app.show_status_message = lambda *args, **kwargs: app.messages.append((args, kwargs))
    return app


def test_container_audit_keeps_worker_registry_import_compatibility():
    assert WorkerRegistry is worker_registry.WorkerRegistry


def test_main_checks_updates_before_running_app(monkeypatch):
    calls = []

    class FakeApp:
        def __init__(self):
            calls.append("init")

        def run(self):
            calls.append("run")

    monkeypatch.setattr(container_audit_module, "check_and_apply_updates", lambda: calls.append("updates"))
    monkeypatch.setattr(container_audit_module, "ContainerAudit", FakeApp)

    container_audit_module.main()

    assert calls == ["updates", "init", "run"]


def test_check_and_apply_updates_skips_source_mode_before_network(monkeypatch):
    monkeypatch.setattr(container_audit_module.sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        container_audit_module,
        "check_for_updates",
        lambda: (_ for _ in ()).throw(AssertionError("source mode should not check releases")),
    )

    container_audit_module.check_and_apply_updates()


def test_audio_feedback_init_failure_is_nonfatal(monkeypatch):
    app = _headless_app()
    warnings = []
    monkeypatch.setattr(container_audit_module.pygame, "init", lambda: None)
    monkeypatch.setattr(
        container_audit_module.pygame.mixer,
        "init",
        lambda: (_ for _ in ()).throw(container_audit_module.pygame.error("no audio device")),
    )
    monkeypatch.setattr(
        container_audit_module.pygame.mixer,
        "Sound",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Sound should not load after init failure")),
    )
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._load_audio_feedback()

    assert app.success_sound is None
    assert app.error_sound is None
    assert warnings


def test_update_asset_lookup_requires_matching_sha256_asset():
    payload = {
        "assets": [
            {
                "name": "Container_Audit-v2.0.10.zip",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
            },
            {
                "name": "Container_Audit-v2.0.10.zip.sha256",
                "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
            },
        ]
    }

    assert container_audit_module._find_release_asset_urls(payload) == (
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip",
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/Container_Audit-v2.0.10.zip.sha256",
    )


def test_update_checksum_verification_rejects_mismatch(tmp_path):
    zip_path = tmp_path / "update.zip"
    zip_path.write_bytes(b"zip-bytes")
    good_hash = hashlib.sha256(b"zip-bytes").hexdigest()
    bad_hash = hashlib.sha256(b"other").hexdigest()

    container_audit_module._verify_update_checksum(str(zip_path), f"{good_hash}  update.zip")
    with pytest.raises(ValueError, match="일치하지 않습니다"):
        container_audit_module._verify_update_checksum(str(zip_path), f"{bad_hash}  update.zip")


def test_update_download_rejects_content_length_over_limit(tmp_path):
    zip_path = tmp_path / "update.zip"
    response = FakeDownloadResponse([], headers={"Content-Length": "5"})

    with pytest.raises(ValueError, match="다운로드 크기"):
        container_audit_module._write_update_download(response, str(zip_path), max_bytes=4)

    assert not zip_path.exists()


def test_update_download_removes_partial_file_when_stream_exceeds_limit(tmp_path):
    zip_path = tmp_path / "update.zip"
    response = FakeDownloadResponse([b"12", b"345"])

    with pytest.raises(ValueError, match="다운로드 크기"):
        container_audit_module._write_update_download(response, str(zip_path), max_bytes=4)

    assert not zip_path.exists()


def test_updater_script_backs_up_before_copy_and_rolls_back_on_failure():
    script = container_audit_module._build_updater_script(
        executable_name="Container_Audit.exe",
        application_path=r"C:\Company Apps\Container Audit",
        new_program_folder_path=r"C:\Temp\update\extracted\Container_Audit",
        update_temp_root=r"C:\Temp\update",
        current_pid=12345,
    )

    assert 'set "CURRENT_PID=12345"' in script
    assert "taskkill /F /PID %CURRENT_PID%" in script
    assert '/IM "Container_Audit.exe"' not in script
    assert 'set "BACKUP_PATH=C:\\Temp\\update\\backup"' in script
    assert 'set "PRESERVE_PATH=C:\\Temp\\update\\preserve_config"' in script
    assert 'robocopy "%APP_PATH%" "%BACKUP_PATH%" /MIR' in script
    assert "if errorlevel 8 goto BACKUP_FAILED" in script
    assert 'robocopy "%APP_PATH%\\config" "%PRESERVE_PATH%\\config" "container_audit_settings.json"' in script
    assert 'robocopy "%APP_PATH%\\config" "%PRESERVE_PATH%\\config" "worker_registry.json"' in script
    assert 'robocopy "%APP_PATH%\\config" "%PRESERVE_PATH%\\config" "best_time_records.json"' in script
    assert 'robocopy "%APP_PATH%\\config\\parked_trays" "%PRESERVE_PATH%\\config\\parked_trays" /MIR' in script
    assert 'robocopy "%NEW_PATH%" "%APP_PATH%" /MIR' in script
    assert "if errorlevel 8 goto ROLLBACK" in script
    assert 'robocopy "%PRESERVE_PATH%\\config" "%APP_PATH%\\config" "container_audit_settings.json"' in script
    assert 'robocopy "%PRESERVE_PATH%\\config\\parked_trays" "%APP_PATH%\\config\\parked_trays" /MIR' in script
    assert "xcopy" not in script
    assert ":ROLLBACK" in script
    assert ":PRESERVE_FAILED" in script
    assert script.index('robocopy "%APP_PATH%" "%BACKUP_PATH%" /MIR') < script.index(
        'robocopy "%APP_PATH%\\config" "%PRESERVE_PATH%\\config" "container_audit_settings.json"'
    )
    assert script.index('robocopy "%APP_PATH%\\config\\parked_trays" "%PRESERVE_PATH%\\config\\parked_trays" /MIR') < script.index(
        'robocopy "%NEW_PATH%" "%APP_PATH%" /MIR'
    )
    assert script.index('robocopy "%NEW_PATH%" "%APP_PATH%" /MIR') < script.index(
        'robocopy "%PRESERVE_PATH%\\config" "%APP_PATH%\\config" "container_audit_settings.json"'
    )
    assert script.index('robocopy "%PRESERVE_PATH%\\config\\parked_trays" "%APP_PATH%\\config\\parked_trays" /MIR') < script.index(
        'rmdir /s /q "%UPDATE_TEMP_ROOT%"'
    )
    assert script.index("exit /b 0") < script.index(":ROLLBACK")
    assert 'robocopy "%BACKUP_PATH%" "%APP_PATH%" /MIR' in script
    assert "if errorlevel 8 goto ROLLBACK_FAILED" in script


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("application_path", r"C:\Company%Apps\Container Audit"),
        ("new_program_folder_path", r"C:\Temp\update&run\Container_Audit"),
        ("update_temp_root", "C:\\Temp\\update\nnext"),
        ("executable_name", "Container_Audit^2.exe"),
    ],
)
def test_updater_script_rejects_batch_metacharacter_paths(field, value):
    kwargs = {
        "executable_name": "Container_Audit.exe",
        "application_path": r"C:\Company Apps\Container Audit",
        "new_program_folder_path": r"C:\Temp\update\extracted\Container_Audit",
        "update_temp_root": r"C:\Temp\update",
        "current_pid": 1234,
    }
    kwargs[field] = value

    with pytest.raises(ValueError, match="배치 문자"):
        container_audit_module._build_updater_script(**kwargs)


def test_download_and_apply_update_writes_updater_under_temp_root(tmp_path, monkeypatch):
    update_root = tmp_path / "update-root"
    popen_paths = []
    requests_seen = []
    monkeypatch.setattr(container_audit_module.sys, "frozen", True, raising=False)

    class FakeResponse:
        def __init__(self, *, content=b"zip-bytes", text=""):
            self.headers = {}
            self._content = text.encode("utf-8") if text else content
            self.text = text

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            return iter([self._content])

    def fake_mkdtemp(*args, **kwargs):
        update_root.mkdir()
        return str(update_root)

    def fake_extract(zip_path, destination):
        extracted = tmp_path / "update-root" / "extracted" / "Container_Audit"
        extracted.mkdir(parents=True)
        (extracted / "Container_Audit.exe").write_text("exe", encoding="utf-8")
        return extracted.parent

    monkeypatch.setattr(container_audit_module.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(
        container_audit_module.requests,
        "get",
        lambda url, **kwargs: requests_seen.append((url, kwargs)) or (
            FakeResponse(text=f"{hashlib.sha256(b'zip-bytes').hexdigest()}  update.zip")
            if url.endswith(".sha256")
            else FakeResponse()
        ),
    )
    monkeypatch.setattr(container_audit_module, "safe_extract_update_zip", fake_extract)
    monkeypatch.setattr(container_audit_module.subprocess, "Popen", lambda path, **kwargs: popen_paths.append(path))

    with pytest.raises(SystemExit):
        container_audit_module.download_and_apply_update(
            "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip",
            checksum_url="https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip.sha256",
        )

    updater_path = update_root / "updater.bat"
    assert [call[0] for call in requests_seen] == [
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip",
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip.sha256",
    ]
    assert popen_paths == [[str(updater_path)]]
    assert updater_path.is_file()
    assert update_root.exists()


def test_update_checksum_response_rejects_oversized_stream():
    response = FakeDownloadResponse([b"123", b"45"], headers={})

    with pytest.raises(ValueError, match="체크섬 크기"):
        container_audit_module._read_update_checksum_response(response, max_bytes=4)


def test_download_and_apply_update_cleans_temp_root_when_extract_fails(tmp_path, monkeypatch):
    update_root = tmp_path / "update-root"
    requests_seen = []
    monkeypatch.setattr(container_audit_module.sys, "frozen", True, raising=False)

    class FakeResponse:
        def __init__(self, *, content=b"zip-bytes", text=""):
            self.headers = {}
            self._content = text.encode("utf-8") if text else content

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            return iter([self._content])

    def fake_mkdtemp(*args, **kwargs):
        update_root.mkdir()
        return str(update_root)

    monkeypatch.setattr(container_audit_module.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(
        container_audit_module.requests,
        "get",
        lambda url, **kwargs: requests_seen.append((url, kwargs)) or (
            FakeResponse(text=f"{hashlib.sha256(b'zip-bytes').hexdigest()}  update.zip")
            if url.endswith(".sha256")
            else FakeResponse()
        ),
    )
    monkeypatch.setattr(
        container_audit_module,
        "safe_extract_update_zip",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad archive")),
    )
    monkeypatch.setattr(
        container_audit_module.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("updater should not launch after extract failure")),
    )
    errors = []

    class FakeTk:
        def withdraw(self):
            return None

        def destroy(self):
            return None

    monkeypatch.setattr(container_audit_module.tk, "Tk", FakeTk)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    container_audit_module.download_and_apply_update(
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip",
        checksum_url="https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip.sha256",
    )

    assert requests_seen[1][1]["stream"] is True
    assert errors
    assert not update_root.exists()


def test_download_and_apply_update_rejects_source_mode_before_network(monkeypatch):
    monkeypatch.setattr(container_audit_module.sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        container_audit_module.requests,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("download should not start in source mode")),
    )
    monkeypatch.setattr(
        container_audit_module,
        "safe_extract_update_zip",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("extract should not start in source mode")),
    )
    monkeypatch.setattr(
        container_audit_module.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("updater should not launch in source mode")),
    )
    errors = []

    class FakeTk:
        def withdraw(self):
            return None

        def destroy(self):
            return None

    monkeypatch.setattr(container_audit_module.tk, "Tk", FakeTk)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    container_audit_module.download_and_apply_update(
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip",
        checksum_url="https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip.sha256",
    )

    assert errors
    assert "소스 실행 모드" in errors[0][1]


def test_download_and_apply_update_requires_checksum_before_network_or_extract(monkeypatch):
    monkeypatch.setattr(
        container_audit_module.requests,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("download should not start without checksum")),
    )
    monkeypatch.setattr(
        container_audit_module,
        "safe_extract_update_zip",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("extract should not start without checksum")),
    )
    monkeypatch.setattr(
        container_audit_module.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("updater should not launch without checksum")),
    )
    errors = []

    class FakeTk:
        def withdraw(self):
            return None

        def destroy(self):
            return None

    monkeypatch.setattr(container_audit_module.tk, "Tk", FakeTk)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    container_audit_module.download_and_apply_update(
        "https://github.com/KMTechn/Container_Audit/releases/download/v2.0.10/update.zip",
        checksum_url=None,
    )

    assert errors
    assert "체크섬 URL" in errors[0][1]


def test_check_for_updates_skips_zip_without_checksum(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "tag_name": "v9.9.9",
                "assets": [
                    {
                        "name": "Container_Audit-v9.9.9.zip",
                        "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v9.9.9/Container_Audit-v9.9.9.zip",
                    }
                ],
            }

    monkeypatch.setattr(container_audit_module.requests, "get", lambda *args, **kwargs: FakeResponse())

    assert container_audit_module.check_for_updates() == (None, None, None)


def test_check_for_updates_skips_non_matching_zip_assets(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "tag_name": "v9.9.9",
                "assets": [
                    {
                        "name": "Container_Audit-v1.0.0.zip",
                        "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v1.0.0/Container_Audit-v1.0.0.zip",
                    },
                    {
                        "name": "Container_Audit-v1.0.0.zip.sha256",
                        "browser_download_url": "https://github.com/KMTechn/Container_Audit/releases/download/v1.0.0/Container_Audit-v1.0.0.zip.sha256",
                    },
                ],
            }

    monkeypatch.setattr(container_audit_module.requests, "get", lambda *args, **kwargs: FakeResponse())

    assert container_audit_module.check_for_updates() == (None, None, None)


@pytest.mark.parametrize("payload", [{}, [], {"tag_name": ""}])
def test_check_for_updates_handles_malformed_release_payload(monkeypatch, payload):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    monkeypatch.setattr(container_audit_module.requests, "get", lambda *args, **kwargs: FakeResponse())

    assert container_audit_module.check_for_updates() == (None, None, None)


def test_worker_registry_registers_normalized_unique_workers(tmp_path):
    registry_path = tmp_path / "worker_registry.json"
    registry = WorkerRegistry(str(registry_path))

    assert registry.list_workers() == []
    assert registry.register(" 홍길동 ") == "홍길동"
    assert registry.register("홍길동") == "홍길동"
    assert registry.list_workers() == ["홍길동"]

    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    assert [entry["name"] for entry in payload["workers"]] == ["홍길동"]
    assert payload["workers"][0]["active"] is True


def test_atomic_write_json_replaces_existing_file_and_removes_temp(tmp_path):
    target = tmp_path / "nested" / "state.json"
    storage_utils.atomic_write_json(target, {"old": True}, indent=2)

    storage_utils.atomic_write_json(target, {"new": True}, indent=2, ensure_ascii=False)

    assert json.loads(target.read_text(encoding="utf-8")) == {"new": True}
    assert list(target.parent.glob("*.tmp")) == []


def test_atomic_write_json_uses_unique_temp_paths_for_repeated_writes(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    observed = []
    original_replace = storage_utils.os.replace

    def capture_replace(src, dst):
        observed.append((Path(src).name, Path(dst).name))
        original_replace(src, dst)

    monkeypatch.setattr(storage_utils.os, "replace", capture_replace)

    storage_utils.atomic_write_json(target, {"step": 1})
    storage_utils.atomic_write_json(target, {"step": 2})

    assert observed[0][0].startswith("state.json.")
    assert observed[1][0].startswith("state.json.")
    assert observed[0][0].endswith(".tmp")
    assert observed[1][0].endswith(".tmp")
    assert observed[0][0] != observed[1][0]
    assert observed[0][1] == "state.json"
    assert json.loads(target.read_text(encoding="utf-8")) == {"step": 2}
    assert list(target.parent.glob("*.tmp")) == []


def test_atomic_write_json_keeps_existing_file_when_serialization_fails(tmp_path):
    target = tmp_path / "state.json"
    storage_utils.atomic_write_json(target, {"old": True}, indent=2)

    with pytest.raises(TypeError):
        storage_utils.atomic_write_json(target, {"bad": object()}, indent=2)

    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}


def test_atomic_write_json_fsyncs_before_replace(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(storage_utils.os, "fsync", lambda fd: calls.append(fd))

    storage_utils.atomic_write_json(tmp_path / "state.json", {"ok": True})

    assert calls


def test_synchronous_log_event_writes_durable_csv_entry(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.log_file_path = str(tmp_path / "events.csv")

    assert app._log_event("TRAY_COMPLETE", {"scan_count": 1}, synchronous=True) is True

    with open(app.log_file_path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["worker_name"] == "홍길동"
    assert rows[0]["event"] == "TRAY_COMPLETE"
    details = json.loads(rows[0]["details"])
    assert details["scan_count"] == 1
    assert details["dispatch_key"] == "container_audit|legacy_transfer_csv|TRAY_COMPLETE"


def test_synchronous_log_event_reports_failure_without_log_path():
    app = _headless_app()
    app.worker_name = "홍길동"
    app.log_file_path = ""

    assert app._log_event("TRAY_COMPLETE", {"scan_count": 1}, synchronous=True) is False


@pytest.mark.parametrize("bad_number", [float("nan"), float("inf"), float("-inf")])
def test_log_event_rejects_non_finite_numbers_without_writing_or_queueing(tmp_path, bad_number):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.log_file_path = str(tmp_path / "events.csv")
    app.log_queue = queue.Queue()

    assert app._log_event("SCAN_OK", {"interval_sec": bad_number}, synchronous=True) is False
    assert not Path(app.log_file_path).exists()

    assert app._log_event("SCAN_OK", {"interval_sec": bad_number}) is False
    assert app.log_queue.empty()
    assert not Path(app.log_file_path).exists()


def test_async_log_event_uses_path_captured_at_queue_time(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    first_path = tmp_path / "first.csv"
    second_path = tmp_path / "second.csv"
    app.log_file_path = str(first_path)
    app.log_queue = queue.Queue()

    assert app._log_event("SCAN_OK", {"barcode": "BC-1"}) is True
    app.log_file_path = str(second_path)
    app.log_queue.put(None)

    app._event_log_writer()

    with open(first_path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert [row["event"] for row in rows] == ["SCAN_OK"]
    assert not second_path.exists()


def test_event_log_store_appends_header_once(tmp_path):
    log_path = tmp_path / "events.csv"

    event_log_store.append_event_log_entry(
        str(log_path),
        {"timestamp": "1", "worker_name": "a", "event": "SCAN_OK", "details": "{}"},
    )
    event_log_store.append_event_log_entry(
        str(log_path),
        {"timestamp": "2", "worker_name": "a", "event": "TRAY_COMPLETE", "details": "{}"},
    )

    with open(log_path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert [row["event"] for row in rows] == ["SCAN_OK", "TRAY_COMPLETE"]


def test_event_log_store_fsyncs_only_for_durable_appends(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(event_log_store.os, "fsync", lambda fd: calls.append(fd))
    log_path = tmp_path / "events.csv"

    event_log_store.append_event_log_entry(
        str(log_path),
        {"timestamp": "1", "worker_name": "a", "event": "SCAN_OK", "details": "{}"},
    )
    assert calls == []

    event_log_store.append_event_log_entry(
        str(log_path),
        {"timestamp": "2", "worker_name": "a", "event": "TRAY_COMPLETE", "details": "{}"},
        durable=True,
    )
    assert calls


def test_tray_session_state_round_trips_without_ui():
    start_time = datetime.datetime(2026, 6, 22, 9, 0, 0)
    scan_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[scan_time],
        tray_size=60,
        mismatch_error_count=1,
        total_idle_seconds=2.5,
        stopwatch_seconds=60.0,
        start_time=start_time,
        has_error_or_reset=True,
        is_test_tray=False,
        is_partial_submission=True,
    )

    state = tray_state.tray_session_to_state(session, worker_name="홍길동")
    restored = tray_state.tray_session_from_state(
        state,
        session_factory=TraySession,
        default_tray_size=60,
    )

    assert state["worker_name"] == "홍길동"
    assert state["scan_times"] == [scan_time.isoformat()]
    assert state["start_time"] == start_time.isoformat()
    assert restored.master_label_code == session.master_label_code
    assert restored.scanned_barcodes == ["BC-1"]
    assert restored.scan_times == [scan_time]
    assert restored.is_restored_session is True
    assert restored.is_partial_submission is True


def test_product_barcodes_from_completion_supports_current_and_legacy_keys():
    assert event_payloads.product_barcodes_from_completion({"product_barcodes": ["P1"]}) == ["P1"]
    assert event_payloads.product_barcodes_from_completion({"product_barcodes": [], "scanned_product_barcodes": ["P2"]}) == ["P2"]
    assert event_payloads.product_barcodes_from_completion({"scanned_product_barcodes": ["P2"]}) == ["P2"]
    assert event_payloads.product_barcodes_from_completion({"scanned_barcodes": ["P3"]}) == ["P3"]
    assert event_payloads.product_barcodes_from_completion(
        {"product_barcodes": ["P1"], "scanned_product_barcodes": ["P1"]}
    ) == ["P1"]
    assert event_payloads.product_barcodes_from_completion({"product_barcodes": "not-a-list"}) == []


def test_product_barcodes_from_completion_rejects_conflicting_or_malformed_aliases():
    with pytest.raises(ValueError, match="aliases conflict"):
        event_payloads.product_barcodes_from_completion(
            {"product_barcodes": ["P1"], "scanned_product_barcodes": ["P2"]}
        )
    with pytest.raises(ValueError, match="text values"):
        event_payloads.product_barcodes_from_completion({"product_barcodes": ["P1", 2]})
    with pytest.raises(ValueError, match="must be unique"):
        event_payloads.product_barcodes_from_completion({"product_barcodes": ["P1", "P1"]})


def test_build_master_label_replacement_detail_preserves_correction_identity():
    original_details = {
        "transfer_id": "transfer-1",
        "master_label_code": "OLD-LABEL",
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
    }

    detail = event_payloads.build_master_label_replacement_detail(
        original_details=original_details,
        old_label="OLD-LABEL",
        new_label="NEW-LABEL",
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id="events.csv",
        source_row_number=7,
        source_byte_offset=123,
        operator="홍길동",
        stable_hash_func=event_contracts.stable_hash,
        old_row_hash="old-row-hash",
        old_qty=2,
        new_qty=2,
        additional_items=["AAA2270730100-003"],
        removed_items=["AAA2270730100-001"],
    )

    corrected_details = dict(original_details)
    corrected_details["master_label_code"] = "NEW-LABEL"
    corrected_details["scanned_product_barcodes"] = ["AAA2270730100-002", "AAA2270730100-003"]
    corrected_details["product_barcodes"] = ["AAA2270730100-002", "AAA2270730100-003"]
    corrected_details["scan_count"] = 2
    corrected_details["barcode_count"] = 2

    assert detail["transfer_id"] == "transfer-1"
    assert detail["item_code"] == "AAA2270730100"
    assert detail["product_barcodes"] == ["AAA2270730100-002", "AAA2270730100-003"]
    assert detail["projection_schema_version"] == "container-audit-corrected-completion-v1"
    assert detail["corrected_completion_projection"] == corrected_details
    assert detail["old_master_label"] == "OLD-LABEL"
    assert detail["new_master_label"] == "NEW-LABEL"
    assert detail["original_event_identity"]["row_hash"] == "old-row-hash"
    assert detail["original_event_identity"]["raw_event_name"] == "TRAY_COMPLETE"
    assert detail["supersedes_identity"]["old_payload_hash"] == event_contracts.stable_hash(original_details)
    assert detail["new_payload_hash"] == event_contracts.stable_hash(corrected_details)
    assert detail["reason"] == "operator_master_label_replacement"


def test_build_master_label_replacement_detail_hashes_new_quantity_projection():
    original_details = {
        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        "scanned_product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        "scan_count": 2,
        "tray_capacity": 2,
        "barcode_count": 2,
        "master_label_fields": {"CLC": "AAA2270730100", "QT": "2"},
    }
    new_label = "PHS=1|CLC=AAA2270730100|QT=3"

    detail = event_payloads.build_master_label_replacement_detail(
        original_details=original_details,
        old_label=original_details["master_label_code"],
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id="events.csv",
        source_row_number=2,
        source_byte_offset=123,
        operator="worker",
        stable_hash_func=event_contracts.stable_hash,
        old_qty=2,
        new_qty=3,
        additional_items=["AAA2270730100-003"],
    )

    expected = dict(original_details)
    expected.update(
        {
            "master_label_code": new_label,
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002", "AAA2270730100-003"],
            "scanned_product_barcodes": ["AAA2270730100-001", "AAA2270730100-002", "AAA2270730100-003"],
            "scan_count": 3,
            "tray_capacity": 3,
            "barcode_count": 3,
            "master_label_fields": {"PHS": "1", "CLC": "AAA2270730100", "QT": "3"},
        }
    )
    assert detail["new_payload_hash"] == event_contracts.stable_hash(expected)
    assert detail["new_payload_hash"] == event_contracts.stable_hash(detail["corrected_completion_projection"])


def test_build_master_label_replacement_detail_backfills_projection_item_code_from_label_clc():
    original_details = {
        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        "scan_count": 2,
    }
    new_label = "PHS=1|CLC=AAA2270730100|QT=2"

    detail = event_payloads.build_master_label_replacement_detail(
        original_details=original_details,
        old_label=original_details["master_label_code"],
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id="events.csv",
        source_row_number=2,
        source_byte_offset=123,
        operator="worker",
        stable_hash_func=event_contracts.stable_hash,
        old_qty=2,
        new_qty=2,
    )

    assert detail["item_code"] == "AAA2270730100"
    assert detail["corrected_completion_projection"]["item_code"] == "AAA2270730100"
    assert detail["new_payload_hash"] == event_contracts.stable_hash(detail["corrected_completion_projection"])


def test_build_master_label_replacement_detail_accepts_canonical_equivalent_old_label():
    original_details = {
        "master_label_code": '{"CLC":"AAA2270730100","QT":"2"}',
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
    }

    detail = event_payloads.build_master_label_replacement_detail(
        original_details=original_details,
        old_label="QT=2|CLC=AAA2270730100",
        new_label="PHS=1|CLC=AAA2270730100|QT=2",
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id="events.csv",
        source_row_number=2,
        source_byte_offset=10,
        operator="worker",
        stable_hash_func=event_contracts.stable_hash,
        old_qty=2,
        new_qty=2,
    )

    assert detail["old_master_label"] == "QT=2|CLC=AAA2270730100"


def test_build_master_label_replacement_detail_rejects_old_label_mismatch():
    original_details = {
        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
    }

    with pytest.raises(ValueError, match="old master label"):
        event_payloads.build_master_label_replacement_detail(
            original_details=original_details,
            old_label="PHS=1|CLC=BBB2270730100|QT=2",
            new_label="PHS=1|CLC=AAA2270730100|QT=2",
            source_system="container_audit",
            source_transport_or_dataset="legacy_transfer_csv",
            source_file_id="events.csv",
            source_row_number=2,
            source_byte_offset=10,
            operator="worker",
            stable_hash_func=event_contracts.stable_hash,
            old_qty=2,
            new_qty=2,
        )


@pytest.mark.parametrize(
    ("additional_items", "removed_items", "new_qty", "message"),
    [
        (["AAA2270730100-003", "AAA2270730100-003"], [], 4, "additional product barcodes must be unique"),
        (["AAA2270730100-001"], [], 3, "already exists"),
        ([], ["AAA2270730100-X"], 1, "not in original completion"),
        (["AAA2270730100-003"], [], 2, "does not match new quantity"),
    ],
)
def test_build_master_label_replacement_detail_rejects_invalid_delta(
    additional_items,
    removed_items,
    new_qty,
    message,
):
    original = {
        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
    }

    with pytest.raises(ValueError, match=message):
        event_payloads.build_master_label_replacement_detail(
            original_details=original,
            old_label="PHS=1|CLC=AAA2270730100|QT=2",
            new_label="PHS=1|CLC=AAA2270730100|QT=2",
            source_system="container_audit",
            source_transport_or_dataset="legacy_transfer_csv",
            source_file_id="events.csv",
            source_row_number=2,
            source_byte_offset=10,
            operator="worker",
            stable_hash_func=event_contracts.stable_hash,
            old_qty=2,
            new_qty=new_qty,
            additional_items=additional_items,
            removed_items=removed_items,
        )


def test_build_master_label_replacement_detail_rejects_conflicting_barcode_aliases():
    with pytest.raises(ValueError, match="aliases conflict"):
        event_payloads.build_master_label_replacement_detail(
            original_details={
                "master_label_code": "OLD",
                "product_barcodes": ["BC-1"],
                "scanned_product_barcodes": ["BC-2"],
            },
            old_label="OLD",
            new_label="PHS=1|CLC=AAA2270730100|QT=1",
            source_system="container_audit",
            source_transport_or_dataset="legacy_transfer_csv",
            source_file_id="events.csv",
            source_row_number=2,
            source_byte_offset=10,
            operator="worker",
            stable_hash_func=event_contracts.stable_hash,
            old_qty=1,
            new_qty=1,
        )


def test_build_master_label_replacement_detail_rejects_cross_item_added_barcode():
    original = {
        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=1",
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001"],
    }

    with pytest.raises(ValueError, match="additional product barcode item_code mismatch"):
        event_payloads.build_master_label_replacement_detail(
            original_details=original,
            old_label=original["master_label_code"],
            new_label="PHS=1|CLC=AAA2270730100|QT=2",
            source_system="container_audit",
            source_transport_or_dataset="legacy_transfer_csv",
            source_file_id="events.csv",
            source_row_number=2,
            source_byte_offset=10,
            operator="worker",
            stable_hash_func=event_contracts.stable_hash,
            old_qty=1,
            new_qty=2,
            additional_items=["BBB2270730100-001"],
        )


def _write_session_history_row(
    path,
    *,
    timestamp,
    master_label,
    item_code,
    worker_name="홍길동",
    is_test=False,
    partial=False,
    clean=True,
    scan_count=60,
    tray_capacity=60,
    work_time_sec=360.0,
    product_barcodes=None,
    barcode_count=None,
):
    details = {
        "master_label_code": master_label,
        "item_code": item_code,
        "item_name": "fixture item",
        "scan_count": scan_count,
        "tray_capacity": tray_capacity,
        "work_time_sec": work_time_sec,
        "has_error_or_reset": not clean,
        "is_partial_submission": partial,
        "is_restored_session": False,
        "is_test_tray": is_test,
    }
    if product_barcodes is not None:
        details["product_barcodes"] = product_barcodes
        details["scanned_product_barcodes"] = product_barcodes
    if barcode_count is not None:
        details["barcode_count"] = barcode_count
    file_exists = path.exists()
    with path.open("a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        if not file_exists:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp": timestamp.isoformat(),
                "worker_name": worker_name,
                "event": "TRAY_COMPLETE",
                "details": json.dumps(details, ensure_ascii=False),
            }
        )


def test_session_history_loads_daily_summary_completed_labels_and_clean_times(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label='{"QT":"60","CLC":"AAA2270730100"}',
        item_code="AAA2270730100",
    )
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 10, 0, 0),
        master_label="PHS=1|CLC=BBB2270730100|QT=60",
        item_code="BBB2270730100",
        is_test=True,
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.log_file_path.endswith("이적작업이벤트로그_홍길동_20260623.csv")
    assert history.total_tray_count == 1
    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert history.work_summary["BBB2270730100"]["test_count"] == 1
    assert history.completed_tray_times == [360.0]
    assert label_qr.canonical_master_label_key('{"CLC":"AAA2270730100","QT":"60"}') in history.completed_master_labels
    assert label_qr.canonical_master_label_key("PHS=1|CLC=BBB2270730100|QT=60") not in history.completed_master_labels


def test_session_history_dedupes_replayed_qr_completion_for_summary_and_times(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    replayed_label = "PHS=1|CLC=AAA2270730100|QT=60|WID=REPLAY"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label=replayed_label,
        item_code="AAA2270730100",
        work_time_sec=360.0,
    )
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 5, 0),
        master_label=replayed_label,
        item_code="AAA2270730100",
        work_time_sec=420.0,
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.total_tray_count == 1
    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert history.completed_tray_times == [360.0]
    assert label_qr.canonical_master_label_key(replayed_label) in history.completed_master_labels


def test_session_history_keeps_legacy_raw_completion_rows_conservative(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label="LEGACY-LABEL",
        item_code="AAA2270730100",
        work_time_sec=360.0,
    )
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 5, 0),
        master_label="LEGACY-LABEL",
        item_code="AAA2270730100",
        work_time_sec=420.0,
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.total_tray_count == 2
    assert history.work_summary["AAA2270730100"]["count"] == 2
    assert history.completed_tray_times == [360.0, 420.0]


def test_session_history_uses_all_workers_for_completed_labels_but_current_worker_for_summary(tmp_path):
    today = datetime.date(2026, 6, 23)
    current_log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    other_log_path = tmp_path / "이적작업이벤트로그_김철수_20260623.csv"
    current_label = "PHS=1|CLC=AAA2270730100|QT=60|WID=CURRENT"
    other_label = "PHS=1|CLC=CCC2270730100|QT=60|WID=OTHER"
    _write_session_history_row(
        current_log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label=current_label,
        item_code="AAA2270730100",
    )
    _write_session_history_row(
        other_log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 5, 0),
        master_label=other_label,
        item_code="CCC2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert label_qr.canonical_master_label_key(current_label) in history.completed_master_labels
    assert label_qr.canonical_master_label_key(other_label) in history.completed_master_labels
    assert history.total_tray_count == 1
    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert "CCC2270730100" not in history.work_summary


def test_session_history_excludes_mismatched_row_worker_from_current_summary(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    mismatched_label = "PHS=1|CLC=AAA2270730100|QT=60|WID=MISMATCHED"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label=mismatched_label,
        item_code="AAA2270730100",
        worker_name="김철수",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert label_qr.canonical_master_label_key(mismatched_label) in history.completed_master_labels
    assert history.work_summary == {}
    assert history.total_tray_count == 0
    assert history.completed_tray_times == []


def test_session_history_indexes_old_inspection_completed_labels_without_summary(tmp_path):
    today = datetime.date(2026, 6, 23)
    old_inspection_log_path = tmp_path / "검사작업이벤트로그_홍길동_20260610.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=60|LOT=OLD"
    _write_session_history_row(
        old_inspection_log_path,
        timestamp=datetime.datetime(2026, 6, 10, 9, 0, 0),
        master_label=old_label,
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert label_qr.canonical_master_label_key(old_label) in history.completed_master_labels
    assert history.work_summary == {}
    assert history.total_tray_count == 0


def test_session_history_ignores_future_dated_log_files(tmp_path):
    today = datetime.date(2026, 6, 23)
    future_log_path = tmp_path / "이적작업이벤트로그_홍길동_20260624.csv"
    future_label = "PHS=1|CLC=AAA2270730100|QT=60|WID=FUTURE"
    _write_session_history_row(
        future_log_path,
        timestamp=datetime.datetime(2026, 6, 24, 9, 0, 0),
        master_label=future_label,
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.completed_master_labels == set()
    assert history.work_summary == {}
    assert history.completed_tray_times == []


def test_session_history_ignores_future_timestamp_rows_in_current_log(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    future_label = "PHS=1|CLC=AAA2270730100|QT=60|WID=FUTURE"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 24, 9, 0, 0),
        master_label=future_label,
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert label_qr.canonical_master_label_key(future_label) not in history.completed_master_labels
    assert history.work_summary == {}
    assert history.completed_tray_times == []


def test_session_history_projects_replacement_new_master_label_as_completed(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=60|WID=OLD"
    new_label = "PHS=1|CLC=AAA2270730100|QT=60|WID=NEW"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label=old_label,
        item_code="AAA2270730100",
    )
    with log_path.open("a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:10:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(
                    {"old_master_label": old_label, "new_master_label": new_label},
                    ensure_ascii=False,
                ),
            }
        )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert label_qr.canonical_master_label_key(old_label) in history.completed_master_labels
    assert label_qr.canonical_master_label_key(new_label) in history.completed_master_labels
    assert history.work_summary["AAA2270730100"]["count"] == 1


def test_session_history_rejects_tampered_replacement_projection_hash(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=2|WID=OLD"
    new_label = "PHS=1|CLC=AAA2270730100|QT=2|WID=NEW"
    original_details = {
        "master_label_code": old_label,
        "item_code": "AAA2270730100",
        "item_name": "fixture item",
        "spec": "fixture spec",
        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        "scanned_product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        "scan_count": 2,
        "barcode_count": 2,
        "tray_capacity": 2,
        "work_time_sec": 30,
        "has_error_or_reset": False,
        "is_partial_submission": False,
        "is_restored_session": False,
        "is_test_tray": False,
    }
    replacement_detail = event_payloads.build_master_label_replacement_detail(
        original_details=original_details,
        old_label=old_label,
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id=log_path.name,
        source_row_number=2,
        source_byte_offset=123,
        operator="홍길동",
        stable_hash_func=event_contracts.stable_hash,
    )
    replacement_detail["new_row_hash"] = "tampered-new-row-hash"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:10:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(replacement_detail, ensure_ascii=False),
            }
        )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert label_qr.canonical_master_label_key(old_label) not in history.completed_master_labels
    assert label_qr.canonical_master_label_key(new_label) not in history.completed_master_labels
    assert len(history.load_errors) == 1
    assert "2행 MASTER_LABEL_REPLACEMENT_APPLIED" in history.load_errors[0]


def test_session_history_skips_raw_replacement_label_without_poisoning_completed_labels(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=60|WID=OLD"
    raw_poison_label = "RAW-POISON-LABEL"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:10:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(
                    {"old_master_label": old_label, "new_master_label": raw_poison_label},
                    ensure_ascii=False,
                ),
            }
        )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert label_qr.canonical_master_label_key(old_label) not in history.completed_master_labels
    assert raw_poison_label not in history.completed_master_labels
    assert label_qr.canonical_master_label_key(raw_poison_label) not in history.completed_master_labels
    assert len(history.load_errors) == 1
    assert "2행 MASTER_LABEL_REPLACEMENT_APPLIED" in history.load_errors[0]


def test_session_history_uses_event_tray_capacity_for_clean_time(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label='{"QT":"2","CLC":"AAA2270730100"}',
        item_code="AAA2270730100",
        scan_count=2,
        tray_capacity=2,
        work_time_sec=20.0,
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.completed_tray_times == [20.0]


def test_session_history_uses_item_spec_fallback_for_summary(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(
                    {
                        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
                        "item_code": "AAA2270730100",
                        "item_name": "fixture item",
                        "item_spec": "fixture spec",
                        "scan_count": 60,
                        "tray_capacity": 60,
                        "work_time_sec": 360.0,
                    },
                    ensure_ascii=False,
                ),
            }
        )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.work_summary["AAA2270730100"]["spec"] == "fixture spec"


def test_session_history_ignores_malformed_details_on_irrelevant_events(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T08:59:00",
                "worker_name": "홍길동",
                "event": "WORK_START",
                "details": "",
            }
        )
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert history.load_errors == []


def test_session_history_records_load_error_for_corrupt_complete_row(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": "{not-json}",
            }
        )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.completed_tray_times == []
    assert history.load_errors
    assert "2행" in history.load_errors[0]


def test_session_history_does_not_mark_completed_label_when_timestamp_is_invalid(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    master_label = 'PHS=1|CLC=AAA2270730100|QT=60'
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "not-a-date",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(
                    {
                        "master_label_code": master_label,
                        "item_code": "AAA2270730100",
                        "item_name": "fixture item",
                        "spec": "",
                        "scan_count": 60,
                        "tray_capacity": 60,
                        "work_time_sec": 360.0,
                    },
                    ensure_ascii=False,
                ),
            }
        )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.work_summary == {}
    assert history.completed_master_labels == set()
    assert history.load_errors


def test_session_history_skips_parseable_malformed_complete_row_and_continues(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(
                    {
                        "master_label_code": [],
                        "item_code": [],
                        "item_name": "bad",
                        "scan_count": 60,
                        "tray_capacity": 60,
                        "work_time_sec": 360.0,
                    },
                    ensure_ascii=False,
                ),
            }
        )
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 10, 0, 0),
        master_label="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert history.completed_tray_times == [360.0]
    assert len(history.load_errors) == 1
    assert "2행 TRAY_COMPLETE" in history.load_errors[0]


@pytest.mark.parametrize(
    ("bad_master_label", "bad_item_code", "bad_tray_capacity"),
    [
        ("", "BAD2270730100", 60),
        ("PHS=1|CLC=BAD2270730100|QT=60", "", 60),
        ("PHS=1|CLC=AAA2270730100|QT=60", "BAD2270730100", 60),
        ("PHS=1|CLC=BAD2270730100|QT=30", "BAD2270730100", 60),
    ],
)
def test_session_history_rejects_inconsistent_complete_identity_without_polluting_summary(
    tmp_path,
    bad_master_label,
    bad_item_code,
    bad_tray_capacity,
):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label=bad_master_label,
        item_code=bad_item_code,
        tray_capacity=bad_tray_capacity,
    )
    valid_label = "PHS=1|CLC=AAA2270730100|QT=60"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 10, 0, 0),
        master_label=valid_label,
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert "BAD2270730100" not in history.work_summary
    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert label_qr.canonical_master_label_key(valid_label) in history.completed_master_labels
    if bad_master_label and label_qr.canonical_master_label_key(bad_master_label) != label_qr.canonical_master_label_key(valid_label):
        assert label_qr.canonical_master_label_key(bad_master_label) not in history.completed_master_labels
    assert len(history.load_errors) == 1
    assert "2행 TRAY_COMPLETE" in history.load_errors[0]


@pytest.mark.parametrize(
    "bad_overrides",
    [
        {
            "product_barcodes": ["BAD2270730100-001", "BAD2270730100-001"],
            "barcode_count": 2,
            "scan_count": 2,
        },
        {
            "product_barcodes": ["BAD2270730100-001"],
            "barcode_count": 1,
            "scan_count": 60,
        },
        {
            "product_barcodes": ["BAD2270730100-001", "BAD2270730100-002"],
            "barcode_count": 1,
            "scan_count": 2,
        },
        {
            "product_barcodes": [f"BAD2270730100-{index:03d}" for index in range(61)],
            "barcode_count": 61,
            "scan_count": 61,
        },
    ],
)
def test_session_history_rejects_malformed_complete_counts_without_polluting_summary(tmp_path, bad_overrides):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    bad_label = "PHS=1|CLC=BAD2270730100|QT=60"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label=bad_label,
        item_code="BAD2270730100",
        **bad_overrides,
    )
    valid_label = "PHS=1|CLC=AAA2270730100|QT=60"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 10, 0, 0),
        master_label=valid_label,
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert "BAD2270730100" not in history.work_summary
    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert label_qr.canonical_master_label_key(bad_label) not in history.completed_master_labels
    assert label_qr.canonical_master_label_key(valid_label) in history.completed_master_labels
    assert len(history.load_errors) == 1
    assert "2행 TRAY_COMPLETE" in history.load_errors[0]


@pytest.mark.parametrize(
    "bool_key",
    ["has_error_or_reset", "is_partial_submission", "is_restored_session", "is_test_tray"],
)
def test_session_history_skips_parseable_malformed_boolean_complete_row_and_continues(tmp_path, bool_key):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    malformed_details = {
        "master_label_code": "PHS=1|CLC=BAD2270730100|QT=60",
        "item_code": "BAD2270730100",
        "item_name": "bad",
        "scan_count": 60,
        "tray_capacity": 60,
        "work_time_sec": 360.0,
        "has_error_or_reset": False,
        "is_partial_submission": False,
        "is_restored_session": False,
        "is_test_tray": False,
    }
    malformed_details[bool_key] = "false"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(malformed_details, ensure_ascii=False),
            }
        )
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 10, 0, 0),
        master_label="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert "BAD2270730100" not in history.work_summary
    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert history.total_tray_count == 1
    assert history.completed_tray_times == [360.0]
    assert len(history.load_errors) == 1
    assert "2행 TRAY_COMPLETE" in history.load_errors[0]


def test_session_history_skips_parseable_malformed_replacement_row_and_continues(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps({"old_master_label": [], "new_master_label": {}}, ensure_ascii=False),
            }
        )
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 10, 0, 0),
        master_label="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert len(history.load_errors) == 1
    assert "2행 MASTER_LABEL_REPLACEMENT_APPLIED" in history.load_errors[0]


def test_session_history_skips_invalid_work_time_without_losing_summary(tmp_path):
    today = datetime.date(2026, 6, 23)
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    _write_session_history_row(
        log_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label='{"QT":"60","CLC":"AAA2270730100"}',
        item_code="AAA2270730100",
        work_time_sec="bad",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.work_summary["AAA2270730100"]["count"] == 1
    assert history.completed_tray_times == []
    assert any("work_time_sec" in error for error in history.load_errors)


def test_session_history_ignores_backup_suffix_log_files(tmp_path):
    today = datetime.date(2026, 6, 23)
    backup_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv.bak"
    _write_session_history_row(
        backup_path,
        timestamp=datetime.datetime(2026, 6, 23, 9, 0, 0),
        master_label="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
    )

    history = session_history.load_session_history(
        save_folder=tmp_path,
        worker_name="홍길동",
        today=today,
        tray_size=60,
    )

    assert history.work_summary == {}
    assert history.total_tray_count == 0
    assert history.completed_master_labels == set()


def test_app_load_session_state_applies_session_history(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.TRAY_SIZE = 60
    app.COLOR_PRIMARY = "primary"
    app.status_messages = []
    app.show_status_message = lambda *args, **kwargs: app.status_messages.append((args, kwargs))
    _write_session_history_row(
        tmp_path / f"이적작업이벤트로그_홍길동_{datetime.date.today().strftime('%Y%m%d')}.csv",
        timestamp=datetime.datetime.combine(datetime.date.today(), datetime.time(9, 0, 0)),
        master_label="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
    )

    app._load_session_state()

    assert app.total_tray_count == 1
    assert app.work_summary["AAA2270730100"]["count"] == 1
    assert app._is_completed_master_label("QT=60|CLC=AAA2270730100|PHS=1") is True
    assert app.status_messages


def test_item_catalog_finds_exact_code_and_code_inside_product_barcode():
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"},
            {"Item Code": "BBB2270730100", "Item Name": "other item", "Spec": "other spec"},
        ]
    )

    assert catalog.find_by_code("AAA2270730100")["Item Name"] == "fixture item"
    assert catalog.find_in_barcode("PREFIX-AAA2270730100-SUFFIX")["Spec"] == "fixture spec"
    assert catalog.matching_codes_in_barcode("AAA2270730100-BBB2270730100") == [
        "AAA2270730100",
        "BBB2270730100",
    ]
    assert catalog.find_in_barcode("AAA2270730100-BBB2270730100") is None
    assert catalog.find_by_code("missing") is None


def test_item_catalog_returns_normalized_item_code_rows():
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": " AAA2270730100 ", "Item Name": "fixture item", "Spec": "fixture spec"},
        ]
    )

    assert catalog.find_by_code("AAA2270730100")["Item Code"] == "AAA2270730100"
    assert catalog.find_in_barcode("SERIAL-AAA2270730100-001")["Item Code"] == "AAA2270730100"
    assert catalog.rows()[0]["Item Code"] == "AAA2270730100"


def test_item_catalog_deduplicates_duplicate_item_codes_for_barcode_matching():
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"},
            {"Item Code": "AAA2270730100", "Item Name": "duplicate fixture", "Spec": "duplicate spec"},
        ]
    )

    assert catalog.matching_codes_in_barcode("PREFIX-AAA2270730100-SUFFIX") == ["AAA2270730100"]
    assert catalog.find_in_barcode("PREFIX-AAA2270730100-SUFFIX")["Item Name"] == "fixture item"


def test_item_catalog_prefers_longest_overlapping_item_code_matches():
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": "AAA227073", "Item Name": "short code", "Spec": "short spec"},
            {"Item Code": "AAA2270730100", "Item Name": "long code", "Spec": "long spec"},
            {"Item Code": "BBB2270730100", "Item Name": "other code", "Spec": "other spec"},
        ]
    )

    assert catalog.matching_codes_in_barcode("PREFIX-AAA2270730100-SUFFIX") == ["AAA2270730100"]
    assert catalog.find_in_barcode("PREFIX-AAA2270730100-SUFFIX")["Item Name"] == "long code"
    assert catalog.matching_codes_in_barcode("AAA2270730100-BBB2270730100") == [
        "AAA2270730100",
        "BBB2270730100",
    ]


def test_item_catalog_keeps_nested_item_code_when_it_appears_separately():
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": "AAA227073", "Item Name": "short code", "Spec": "short spec"},
            {"Item Code": "AAA2270730100", "Item Name": "long code", "Spec": "long spec"},
        ]
    )

    assert catalog.matching_codes_in_barcode("AAA227073-X-AAA2270730100-001") == [
        "AAA227073",
        "AAA2270730100",
    ]
    assert catalog.find_in_barcode("AAA227073-X-AAA2270730100-001") is None


def test_product_exchange_accepts_duplicate_catalog_rows_for_same_item_code():
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"},
            {"Item Code": "AAA2270730100", "Item Name": "duplicate fixture", "Spec": "duplicate spec"},
        ]
    )
    session = ProductExchangeSession(current_step="scan_defective", target_quantity=1)

    result = product_exchange.apply_exchange_scan(
        session,
        "SERIAL-AAA2270730100-001",
        item_catalog=catalog,
        item_code_length=13,
    )

    assert result.status == "accepted"
    assert session.item_code == "AAA2270730100"
    assert session.item_name == "fixture item"


def test_product_exchange_stores_normalized_catalog_item_code():
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": " AAA2270730100 ", "Item Name": "fixture item", "Spec": "fixture spec"},
        ]
    )
    session = ProductExchangeSession(current_step="scan_defective", target_quantity=1)

    defective = product_exchange.apply_exchange_scan(
        session,
        "SERIAL-AAA2270730100-001",
        item_catalog=catalog,
        item_code_length=13,
    )
    good = product_exchange.apply_exchange_scan(
        session,
        "SERIAL-AAA2270730100-002",
        item_catalog=catalog,
        item_code_length=13,
    )

    assert defective.status == "accepted"
    assert good.status == "accepted"
    assert session.item_code == "AAA2270730100"
    assert session.good_barcodes == ["SERIAL-AAA2270730100-002"]


def test_parked_tray_store_saves_and_lists_by_payload_worker(tmp_path):
    store = parked_tray_store.ParkedTrayStore(tmp_path)

    saved_path = store.save_state(
        {
            "worker_name": "홍길동",
            "master_label_code": '{"CLC":"AAA2270730100","QT":"60"}',
            "item_name": "fixture item",
            "scanned_barcodes": ["BC-1", "BC-2"],
        },
        worker_name="홍길동",
        master_label='{"CLC":"AAA2270730100","QT":"60"}',
    )
    store.save_state(
        {
            "worker_name": "다른작업자",
            "master_label_code": '{"CLC":"BBB2270730100","QT":"60"}',
            "item_name": "other item",
            "scanned_barcodes": ["BC-3"],
        },
        worker_name="홍길동",
        master_label='{"CLC":"BBB2270730100","QT":"60"}',
    )

    summaries = store.list_for_worker("홍길동")

    assert saved_path.name.startswith("parked_qr_홍길동_")
    assert [(summary.item_name, summary.scan_count) for summary in summaries] == [("fixture item", 2)]


def test_parked_tray_store_uses_short_hashed_qr_filename_and_finds_legacy_path(tmp_path):
    store = parked_tray_store.ParkedTrayStore(tmp_path)
    long_label = '{"CLC":"AAA2270730100","QT":"60","LOT":"' + ("X" * 240) + '"}'

    saved_path = store.save_state(
        {
            "worker_name": "홍길동",
            "master_label_code": long_label,
            "item_name": "fixture item",
            "scanned_barcodes": [],
        },
        worker_name="홍길동",
        master_label=long_label,
    )

    assert saved_path.name.startswith("parked_qr_홍길동_")
    assert len(saved_path.name) < 120
    assert store.existing_label_path(worker_name="홍길동", master_label=long_label) == saved_path

    short_legacy_label = '{"CLC":"AAA2270730100","QT":"60","LOT":"LEGACY"}'
    legacy_path = store.legacy_deterministic_label_path(worker_name="홍길동", master_label=short_legacy_label)
    storage_utils.atomic_write_json(
        legacy_path,
        {"worker_name": "홍길동", "item_name": "legacy", "scanned_barcodes": []},
        ensure_ascii=False,
    )

    assert store.existing_label_path(worker_name="홍길동", master_label=short_legacy_label) == legacy_path


def test_parked_tray_store_refuses_to_overwrite_existing_qr_label(tmp_path):
    store = parked_tray_store.ParkedTrayStore(tmp_path)
    master_label = '{"CLC":"AAA2270730100","QT":"60"}'
    saved_path = store.save_state(
        {
            "worker_name": "홍길동",
            "master_label_code": master_label,
            "item_name": "original",
            "scanned_barcodes": ["BC-1"],
        },
        worker_name="홍길동",
        master_label=master_label,
    )

    with pytest.raises(FileExistsError):
        store.save_state(
            {
                "worker_name": "홍길동",
                "master_label_code": master_label,
                "item_name": "new",
                "scanned_barcodes": ["BC-2"],
            },
            worker_name="홍길동",
            master_label=master_label,
        )

    saved_state = json.loads(saved_path.read_text(encoding="utf-8"))
    assert saved_state["item_name"] == "original"
    assert saved_state["scanned_barcodes"] == ["BC-1"]


def test_parked_tray_store_ignores_invalid_utf8_files_when_listing_and_matching(tmp_path):
    store = parked_tray_store.ParkedTrayStore(tmp_path)
    invalid_file = tmp_path / "parked_qr_홍길동_invalid_utf8.json"
    invalid_file.write_bytes(b"\xff\xfe\xfa")
    master_label = '{"CLC":"AAA2270730100","QT":"60"}'
    saved_path = store.save_state(
        {
            "worker_name": "홍길동",
            "master_label_code": master_label,
            "item_name": "valid parked",
            "scanned_barcodes": ["BC-1"],
        },
        worker_name="홍길동",
        master_label=master_label,
    )

    summaries = store.list_for_worker("홍길동")

    assert invalid_file.exists()
    assert [(summary.path, summary.item_name, summary.scan_count) for summary in summaries] == [
        (saved_path, "valid parked", 1)
    ]
    assert store.existing_label_path_any_worker(master_label=master_label) == saved_path


def test_parked_tray_store_sanitizes_worker_name_in_paths(tmp_path):
    store = parked_tray_store.ParkedTrayStore(tmp_path)
    unsafe_worker = r"..\다른작업자/shift:a"
    master_label = '{"CLC":"AAA2270730100","QT":"60"}'

    saved_path = store.save_state(
        {
            "worker_name": unsafe_worker,
            "master_label_code": master_label,
            "item_name": "fixture item",
            "scanned_barcodes": ["BC-1"],
        },
        worker_name=unsafe_worker,
        master_label=master_label,
    )

    assert saved_path.resolve().parent == tmp_path.resolve()
    assert saved_path.name.startswith("parked_qr_.._다른작업자_shift_a_")
    assert "\\" not in saved_path.name
    assert "/" not in saved_path.name
    assert store.existing_label_path(worker_name=unsafe_worker, master_label=master_label) == saved_path
    assert [(summary.item_name, summary.scan_count) for summary in store.list_for_worker(unsafe_worker)] == [
        ("fixture item", 1)
    ]


def test_app_current_tray_state_save_restore_round_trips_with_tmp_path(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.COLOR_PRIMARY = "primary"
    app.show_status_message = lambda *args, **kwargs: None
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )

    assert app._save_current_tray_state() is True
    saved_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    app.current_tray = TraySession()
    app._restore_tray_from_state(saved_state)

    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.current_tray.scanned_barcodes == ["BC-1"]
    assert app.current_tray.is_restored_session is True


def test_current_tray_state_save_includes_active_idle_duration(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime.now()],
        total_idle_seconds=5.0,
    )
    app.is_idle = True
    app.last_activity_time = datetime.datetime.now() - datetime.timedelta(minutes=10)

    assert app._save_current_tray_state() is True

    saved_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert 595.0 <= saved_state["total_idle_seconds"] <= 615.0
    assert app.current_tray.total_idle_seconds == 5.0


def test_show_validation_screen_enables_undo_for_restored_scans():
    app = _headless_app()
    app.current_tray = TraySession(master_label_code="ACTIVE", scanned_barcodes=["BC-1", "BC-2"])
    app.undo_button = {"state": container_audit_module.tk.DISABLED}
    app.TRAY_SIZE = 60
    app.clock_job = None
    app.idle_check_job = None
    app.paned_window = type(
        "DummyPaned",
        (),
        {
            "pack": lambda self, *args, **kwargs: None,
            "winfo_children": lambda self: [],
        },
    )()
    app.left_pane = type("DummyPane", (), {"winfo_children": lambda self: []})()
    app.center_pane = type("DummyPane", (), {"winfo_children": lambda self: []})()
    app.right_pane = type("DummyPane", (), {"winfo_children": lambda self: []})()
    app.root = DummyRoot()
    app.scanned_listbox = CapturingListbox()
    app.scan_entry = type("DummyEntry", (), {"focus": lambda self: None})()
    app._clear_main_frames = lambda: None
    app._create_left_sidebar_content = lambda pane: None
    app._create_center_content = lambda pane: None
    app._create_right_sidebar_content = lambda pane: None
    app._set_initial_sash_positions = lambda: None
    app._update_clock = lambda: None
    app._start_idle_checker = lambda: None
    app._update_all_summaries = lambda: None
    app._update_parked_trays_list = lambda: None
    app._update_current_item_label = lambda: None
    app._update_center_display = lambda: None
    app._start_stopwatch = lambda resume=False: None

    app.show_validation_screen()

    assert app.undo_button["state"] == container_audit_module.tk.NORMAL
    assert app.scanned_listbox.rows == ["(2) BC-2", "(1) BC-1"]


def test_start_clock_cancels_existing_clock_job_before_rescheduling():
    app = _headless_app()
    app.root = ClockRoot()
    app.clock_job = "clock-1"
    updates = []

    def fake_update_clock():
        updates.append("update")
        app.clock_job = "clock-2"

    app._update_clock = fake_update_clock

    app._start_clock()

    assert app.root.cancelled == ["clock-1"]
    assert updates == ["update"]
    assert app.clock_job == "clock-2"


def test_load_current_tray_state_discards_state_already_completed(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.log_file_path = str(tmp_path / "events.csv")
    app.log_queue = queue.Queue()
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.completed_master_labels = {"PHS=1|CLC=AAA2270730100|QT=60"}
    app.current_tray = TraySession()
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "홍길동",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("restore prompt should not open")),
    )

    app._load_current_tray_state()

    assert not (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == ""
    with open(app.log_file_path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["event"] == "TRAY_STATE_DISCARDED_AFTER_COMPLETION"
    assert json.loads(rows[0]["details"])["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"


def test_load_current_tray_state_restores_completed_state_when_discard_audit_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = {"PHS=1|CLC=AAA2270730100|QT=60"}
    app.current_tray = TraySession()
    app._log_event = lambda *args, **kwargs: False
    errors = []
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("restore prompt should not open")),
    )
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "홍길동",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )

    app._load_current_tray_state()

    restored_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert restored_state["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"
    assert restored_state["worker_name"] == "홍길동"
    assert app.current_tray.master_label_code == ""
    assert errors[0][0] == "작업 기록 실패"


def test_load_current_tray_state_warns_when_completed_state_delete_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = {"PHS=1|CLC=AAA2270730100|QT=60"}
    app.current_tray = TraySession(master_label_code="STALE", item_code="OLD")
    app._delete_current_tray_state = lambda: False
    app._quarantine_current_tray_state = lambda reason: str(tmp_path / "current.json.bad")
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False, **kwargs: logged.append(
        {"event": event, "detail": {**(detail or {}), **kwargs}, "synchronous": synchronous}
    ) or True
    warnings = []
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("restore prompt should not open")),
    )
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "홍길동",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )

    app._load_current_tray_state()

    assert app.current_tray.master_label_code == ""
    assert logged[0]["event"] == "TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION_RESTORE"
    assert logged[0]["detail"]["quarantined_path"].endswith("current.json.bad")
    assert warnings
    assert warnings[0][0] == "작업 상태 정리 실패"


def test_load_current_tray_state_same_worker_restore_preserves_state_when_restore_audit_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = set()
    app.current_tray = TraySession(master_label_code="STALE", item_code="OLD")
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("restore status should not be shown when restore audit fails")
    )
    app._invalidate_pending_scan_callbacks = lambda: (_ for _ in ()).throw(
        AssertionError("restore callbacks should not be invalidated when restore audit fails")
    )
    logged = []
    errors = []
    app._log_event = lambda event, detail=None, **kwargs: logged.append(
        {"event": event, "detail": detail, "kwargs": kwargs}
    ) and False
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "홍길동",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app._load_current_tray_state()

    saved_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert saved_state["worker_name"] == "홍길동"
    assert saved_state["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.current_tray.master_label_code == ""
    assert logged == [
        {
            "event": "TRAY_RESTORE",
            "detail": {"message": "Same worker restored their session."},
            "kwargs": {"synchronous": True},
        }
    ]
    assert errors[0][0] == "작업 기록 실패"


def test_load_current_tray_state_decline_clears_stale_memory(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = set()
    app.current_tray = TraySession(master_label_code="STALE", item_code="OLD")
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "홍길동",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    logged = []
    app._log_event = lambda event, detail=None, **kwargs: logged.append({"event": event, "detail": detail}) or True
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: False)

    app._load_current_tray_state()

    assert not (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == ""
    assert logged[0]["event"] == "TRAY_DISCARDED_BY_OPERATOR"


def test_load_current_tray_state_decline_preserves_file_when_discard_log_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = set()
    app.current_tray = TraySession(master_label_code="STALE", item_code="OLD")
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "홍길동",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    app._log_event = lambda *args, **kwargs: False
    app._delete_current_tray_state = lambda: (_ for _ in ()).throw(
        AssertionError("state file should not be deleted when discard log fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: False)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app._load_current_tray_state()

    assert (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == "STALE"
    assert errors
    assert errors[0][0] == "작업 기록 실패"


def test_load_current_tray_state_takeover_rewrites_worker_owner(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "새작업자"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = set()
    app.current_tray = TraySession()
    app.COLOR_PRIMARY = "primary"
    app.show_status_message = lambda *args, **kwargs: None
    logged = []
    warnings = []
    app._log_event = lambda event, detail=None, **kwargs: logged.append({"event": event, "detail": detail}) or True
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "이전작업자",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._load_current_tray_state()

    saved_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert saved_state["worker_name"] == "새작업자"
    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert logged[0]["event"] == "TRAY_TAKEOVER"
    assert warnings == []


def test_load_current_tray_state_takeover_rolls_back_owner_when_takeover_log_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "새작업자"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = set()
    app.current_tray = TraySession()
    app.COLOR_PRIMARY = "primary"
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("restore status should not be shown when takeover audit fails")
    )
    logged = []
    errors = []
    app._log_event = lambda event, detail=None, **kwargs: logged.append({"event": event, "detail": detail, "kwargs": kwargs}) and False
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "이전작업자",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app._load_current_tray_state()

    saved_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert saved_state["worker_name"] == "이전작업자"
    assert app.current_tray.master_label_code == ""
    assert logged == [
        {
            "event": "TRAY_TAKEOVER",
            "detail": {"previous_worker": "이전작업자", "new_worker": "새작업자", "item_name": "fixture item"},
            "kwargs": {"synchronous": True},
        }
    ]
    assert errors[0][0] == "작업 기록 실패"


def test_load_current_tray_state_takeover_aborts_when_owner_rewrite_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "새작업자"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = set()
    app.current_tray = TraySession()
    app.COLOR_PRIMARY = "primary"
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("restore status should not be shown before owner rewrite is durable")
    )
    app._save_current_tray_state = lambda: False
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("takeover should not be logged before owner rewrite is durable")
    )
    warnings = []
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "이전작업자",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._load_current_tray_state()

    saved_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert saved_state["worker_name"] == "이전작업자"
    assert app.current_tray.master_label_code == ""
    assert warnings[0][0] == "작업 저장 경고"


def test_load_current_tray_state_takeover_delete_preserves_file_when_discard_log_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "새작업자"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.completed_master_labels = set()
    app.current_tray = TraySession()
    app._log_event = lambda *args, **kwargs: False
    app._delete_current_tray_state = lambda: (_ for _ in ()).throw(
        AssertionError("state file should not be deleted when discard log fails")
    )
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("delete success status should not be shown when discard log fails")
    )
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "이전작업자",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *args, **kwargs: False)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app._load_current_tray_state()

    assert (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == ""
    assert errors
    assert errors[0][0] == "작업 기록 실패"


def test_start_work_stays_on_login_when_restore_takeover_cancel_clears_worker():
    app = _headless_app()
    app.worker_name = ""
    app.worker_entry = type("DummyEntry", (), {"get": lambda self: "홍길동"})()
    app.root = type("DummyRoot", (), {"winfo_exists": lambda self: True})()
    app.paned_window = type("DummyPaned", (), {"winfo_ismapped": lambda self: False})()
    app._ensure_worker_login_name = lambda value: value
    app._load_session_state = lambda: None
    logged = []
    app._log_event = lambda event, detail=None, **kwargs: logged.append(event) or True
    app._load_current_tray_state = lambda: setattr(app, "worker_name", "")
    app.show_validation_screen = lambda: setattr(app, "showed_validation", True)

    app.start_work()

    assert app.worker_name == ""
    assert logged == []
    assert not hasattr(app, "showed_validation")


def _valid_tray_state_payload(**overrides):
    payload = {
        "worker_name": "홍길동",
        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
        "item_code": "AAA2270730100",
        "item_name": "fixture item",
        "item_spec": "fixture spec",
        "scanned_barcodes": ["BC-1"],
        "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
        "tray_size": 60,
        "mismatch_error_count": 0,
        "total_idle_seconds": 0.0,
        "stopwatch_seconds": 30.0,
        "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
        "has_error_or_reset": False,
        "is_test_tray": False,
        "is_partial_submission": False,
    }
    payload.update(overrides)
    return payload


def test_validate_tray_state_rejects_invalid_scan_time():
    state = {
        "worker_name": "홍길동",
        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
        "item_code": "AAA2270730100",
        "item_name": "fixture item",
        "item_spec": "fixture spec",
        "scanned_barcodes": ["BC-1"],
        "scan_times": ["not-a-time"],
        "tray_size": 60,
        "mismatch_error_count": 0,
        "total_idle_seconds": 0.0,
        "stopwatch_seconds": 30.0,
        "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
        "has_error_or_reset": False,
        "is_test_tray": False,
        "is_partial_submission": False,
    }

    with pytest.raises(tray_state.TrayStateValidationError, match="invalid ISO timestamp"):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_validate_tray_state_rejects_mismatched_scan_history():
    state = {
        "worker_name": "홍길동",
        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
        "item_code": "AAA2270730100",
        "item_name": "fixture item",
        "item_spec": "fixture spec",
        "scanned_barcodes": ["BC-1", "BC-2"],
        "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
        "tray_size": 60,
        "mismatch_error_count": 0,
        "total_idle_seconds": 0.0,
        "stopwatch_seconds": 30.0,
        "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
        "has_error_or_reset": False,
        "is_test_tray": False,
        "is_partial_submission": False,
    }

    with pytest.raises(tray_state.TrayStateValidationError, match="length must match"):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_validate_tray_state_rejects_duplicate_scanned_barcodes():
    state = _valid_tray_state_payload(
        scanned_barcodes=["BC-1", "BC-1"],
        scan_times=[
            datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat(),
            datetime.datetime(2026, 6, 22, 9, 2, 0).isoformat(),
        ],
    )

    with pytest.raises(tray_state.TrayStateValidationError, match="duplicates"):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_validate_tray_state_rejects_empty_item_code():
    state = _valid_tray_state_payload(item_code="  ")

    with pytest.raises(tray_state.TrayStateValidationError, match="item_code must not be empty"):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_validate_tray_state_rejects_scan_times_before_start_time():
    state = _valid_tray_state_payload(
        scan_times=[datetime.datetime(2026, 6, 22, 8, 59, 59).isoformat()],
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
    )

    with pytest.raises(tray_state.TrayStateValidationError, match="before start_time"):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_validate_tray_state_rejects_descending_scan_times():
    state = _valid_tray_state_payload(
        scanned_barcodes=["BC-1", "BC-2"],
        scan_times=[
            datetime.datetime(2026, 6, 22, 9, 2, 0).isoformat(),
            datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat(),
        ],
    )

    with pytest.raises(tray_state.TrayStateValidationError, match="chronological order"):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_validate_tray_state_rejects_scan_times_too_far_in_future():
    state = _valid_tray_state_payload(
        scan_times=[datetime.datetime(2026, 6, 22, 10, 10, 1).isoformat()],
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
    )

    with pytest.raises(tray_state.TrayStateValidationError, match="future"):
        tray_state.validate_tray_state(
            state,
            default_tray_size=60,
            now=datetime.datetime(2026, 6, 22, 10, 0, 0),
            future_clock_skew_seconds=600.0,
        )


def test_validate_tray_state_rejects_master_label_item_code_mismatch():
    state = _valid_tray_state_payload(
        master_label_code='{"CLC":"BBB2270730100","QT":"60"}',
        item_code="AAA2270730100",
    )

    with pytest.raises(tray_state.TrayStateValidationError, match="CLC must match item_code"):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_validate_tray_state_rejects_master_label_tray_size_mismatch():
    state = _valid_tray_state_payload(
        master_label_code='{"CLC":"AAA2270730100","QT":"30"}',
        tray_size=60,
    )

    with pytest.raises(tray_state.TrayStateValidationError, match="QT must match tray_size"):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_validate_tray_state_keeps_legacy_label_compatibility():
    state = _valid_tray_state_payload(
        master_label_code="LEGACY-LABEL",
        item_code="DIFFERENT-CODE",
        tray_size=30,
    )

    assert tray_state.validate_tray_state(state, default_tray_size=60) is state


def test_load_current_tray_state_quarantines_invalid_state_without_deleting_evidence(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.current_tray = TraySession()
    storage_utils.atomic_write_json(
        tmp_path / "current.json",
        {
            "worker_name": "홍길동",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1"],
            "scan_times": ["not-a-time"],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
    )
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._load_current_tray_state()

    assert not (tmp_path / "current.json").exists()
    quarantined = list(tmp_path.glob("current.json.bad-*"))
    assert len(quarantined) == 1
    quarantined_state = json.loads(quarantined[0].read_text(encoding="utf-8"))
    assert quarantined_state["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.current_tray.master_label_code == ""
    assert warnings


def test_restore_parked_tray_quarantines_invalid_file_and_keeps_current_state(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.current_tray = TraySession()
    app.TRAY_SIZE = 60
    app.refreshed = False
    app._update_parked_trays_list = lambda: setattr(app, "refreshed", True)
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    storage_utils.atomic_write_json(
        parked_file,
        {
            "worker_name": "홍길동",
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "item_spec": "fixture spec",
            "scanned_barcodes": ["BC-1", "BC-2"],
            "scan_times": [datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat()],
            "tray_size": 60,
            "mismatch_error_count": 0,
            "total_idle_seconds": 0.0,
            "stopwatch_seconds": 30.0,
            "start_time": datetime.datetime(2026, 6, 22, 9, 0, 0).isoformat(),
            "has_error_or_reset": False,
            "is_test_tray": False,
            "is_partial_submission": False,
        },
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert not parked_file.exists()
    quarantined = list(tmp_path.glob("parked_qr_홍길동_fixture.json.bad-*"))
    assert len(quarantined) == 1
    assert app.current_tray.master_label_code == ""
    assert errors
    assert app.refreshed is True


def test_restore_parked_tray_quarantines_invalid_utf8_file_and_keeps_current_state(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app.TRAY_SIZE = 60
    app.refreshed = False
    app._update_parked_trays_list = lambda: setattr(app, "refreshed", True)
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    parked_file = tmp_path / "parked_qr_홍길동_invalid_utf8.json"
    parked_file.write_bytes(b"\xff\xfe\xfa")

    app.restore_parked_tray(str(parked_file))

    assert not parked_file.exists()
    assert list(tmp_path.glob("parked_qr_홍길동_invalid_utf8.json.bad-*"))
    assert app.current_tray.master_label_code == "ACTIVE"
    assert errors
    assert app.refreshed is True


def test_restore_parked_tray_rejects_valid_file_outside_parked_dir(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.current_tray = TraySession()
    app.refreshed = False
    app._update_parked_trays_list = lambda: setattr(app, "refreshed", True)
    app._restore_tray_from_state = lambda state: (_ for _ in ()).throw(
        AssertionError("outside parked tray should not be restored")
    )
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))
    outside_file = tmp_path / "outside_parked.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        outside_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(outside_file))

    assert outside_file.exists()
    assert not (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == ""
    assert app.refreshed is True
    assert warnings


def test_restore_parked_tray_rejects_corrupt_file_outside_parked_dir_without_quarantine(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.current_tray = TraySession()
    app.TRAY_SIZE = 60
    app.refreshed = False
    app._update_parked_trays_list = lambda: setattr(app, "refreshed", True)
    warnings = []
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    outside_file = tmp_path / "outside_corrupt.json"
    outside_file.write_text("{", encoding="utf-8")

    app.restore_parked_tray(str(outside_file))

    assert outside_file.exists()
    assert list(tmp_path.glob("outside_corrupt.json.bad-*")) == []
    assert app.refreshed is True
    assert warnings
    assert errors == []


def test_wakeup_from_waiting_idle_does_not_log_idle_end():
    app = _headless_app()
    app.is_idle = True
    app.current_tray = TraySession()
    app.style_states = []
    app.logged = []
    app.started_idle_checker = []
    app._set_idle_style = lambda is_idle: app.style_states.append(is_idle)
    app._log_event = lambda *args, **kwargs: app.logged.append((args, kwargs))
    app._start_idle_checker = lambda **kwargs: app.started_idle_checker.append(kwargs)

    activity_time = datetime.datetime(2026, 6, 22, 9, 5, 0)
    app._wakeup_from_idle(activity_time=activity_time)

    assert app.is_idle is False
    assert app.logged == []
    assert app.style_states == [False]
    assert app.started_idle_checker == [{"activity_time": activity_time}]


def test_wakeup_from_active_idle_records_previous_idle_duration():
    app = _headless_app()
    app.is_idle = True
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100", total_idle_seconds=5.0)
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 0, 0)
    app.idle_check_job = None
    app.stopwatch_job = None
    app.root = DummyRoot()
    app.COLOR_SUCCESS = "success"
    app.logged = []
    app.saved = False
    app.styles = []
    app.stopwatch_updated = False
    app.status_messages = []
    app._log_event = lambda *args, **kwargs: app.logged.append((args, kwargs))
    app._save_current_tray_state = lambda: setattr(app, "saved", True)
    app._set_idle_style = lambda is_idle: app.styles.append(is_idle)
    app._update_stopwatch = lambda: setattr(app, "stopwatch_updated", True)
    app.show_status_message = lambda *args, **kwargs: app.status_messages.append((args, kwargs))

    app._wakeup_from_idle(activity_time=datetime.datetime(2026, 6, 22, 9, 0, 30))

    assert app.is_idle is False
    assert app.current_tray.total_idle_seconds == 35.0
    assert app.logged[0][0][0] == "IDLE_END"
    assert app.logged[0][1]["detail"]["duration_sec"] == "30.00"
    assert app.saved is True
    assert app.styles == [False]
    assert app.stopwatch_updated is True
    assert app.status_messages


def test_check_for_idle_stops_pending_stopwatch_when_entering_idle():
    class RootWithCancel:
        def __init__(self):
            self.cancelled = []
            self.after_calls = []

        def winfo_exists(self):
            return True

        def after_cancel(self, job):
            self.cancelled.append(job)

        def after(self, delay, callback, *args):
            self.after_calls.append((delay, callback, args))
            return "after-id"

    app = _headless_app()
    app.root = RootWithCancel()
    app.is_idle = False
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app.last_activity_time = datetime.datetime(2026, 6, 22, 8, 0, 0)
    app.IDLE_THRESHOLD_SEC = 60
    app.stopwatch_job = "stopwatch-job"
    app.styles = []
    app.logged = []
    app.saved = False
    app._set_idle_style = lambda is_idle: app.styles.append(is_idle)
    app._log_event = lambda *args, **kwargs: app.logged.append((args, kwargs))
    app._save_current_tray_state = lambda: setattr(app, "saved", True)

    app._check_for_idle()

    assert app.is_idle is True
    assert app.stopwatch_job is None
    assert app.root.cancelled == ["stopwatch-job"]
    assert app.root.after_calls == []
    assert app.styles == [True]
    assert app.logged[0][0][0] == "IDLE_START"
    assert app.saved is True


def test_check_for_idle_ignores_stale_callback_after_idle_checker_stop():
    class RootWithIdleCallbackCapture:
        def __init__(self):
            self.after_calls = []
            self.cancelled = []

        def winfo_exists(self):
            return True

        def after(self, delay, callback, *args):
            self.after_calls.append((delay, callback, args))
            return f"after-{len(self.after_calls)}"

        def after_cancel(self, job):
            self.cancelled.append(job)

    app = _headless_app()
    app.root = RootWithIdleCallbackCapture()
    app.is_idle = False
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app.IDLE_THRESHOLD_SEC = 60
    app.idle_check_job = None
    app.stopwatch_job = "stopwatch-job"
    app.styles = []
    app.logged = []
    app.saved = False
    app._set_idle_style = lambda is_idle: app.styles.append(is_idle)
    app._log_event = lambda *args, **kwargs: app.logged.append((args, kwargs))
    app._save_current_tray_state = lambda: setattr(app, "saved", True)

    app._start_idle_checker(activity_time=datetime.datetime(2026, 6, 22, 8, 0, 0))
    _delay, callback, args = app.root.after_calls[0]
    app._stop_idle_checker()
    app.last_activity_time = datetime.datetime(2026, 6, 22, 8, 0, 0)
    callback(*args)

    assert app.is_idle is False
    assert app.stopwatch_job == "stopwatch-job"
    assert app.styles == []
    assert app.logged == []
    assert app.saved is False
    assert app.root.cancelled == ["after-1"]


def test_change_worker_stays_on_current_worker_when_active_state_save_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app._save_current_tray_state = lambda: False
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("pause log should not be written after failed save")
    )
    app._cancel_all_jobs = lambda: setattr(app, "cancelled", True)
    app.show_worker_input_screen = lambda: setattr(app, "showed_login", True)
    app.errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: app.errors.append(args))

    app.change_worker()

    assert app.worker_name == "홍길동"
    assert not hasattr(app, "cancelled")
    assert not hasattr(app, "showed_login")
    assert app.errors


def test_change_worker_clears_in_memory_tray_after_successful_pause(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app.master_label_replace_state = "awaiting_new_replacement"
    app.replacement_context = {"old_label": "OLD"}
    app._save_current_tray_state = lambda: True
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False, **kwargs: logged.append(
        {"event": event, "detail": {**(detail or {}), **kwargs}, "synchronous": synchronous}
    ) or True
    app._cancel_all_jobs = lambda: setattr(app, "cancelled", True)
    app.show_worker_input_screen = lambda: setattr(app, "showed_login", True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)

    app.change_worker()

    assert app.worker_name == ""
    assert app.current_tray.master_label_code == ""
    assert app.master_label_replace_state is None
    assert app.replacement_context == {}
    assert [entry["event"] for entry in logged] == ["WORK_PAUSE", "HISTORICAL_REPLACE_CANCEL"]
    assert logged[0]["synchronous"] is True
    assert logged[1]["synchronous"] is True
    assert logged[1]["detail"]["reason"] == "worker_change"
    assert app.cancelled is True
    assert app.showed_login is True


def test_change_worker_preserves_active_tray_when_pause_log_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app.master_label_replace_state = None
    app._save_current_tray_state = lambda: True
    app._log_event = lambda *args, **kwargs: False
    app._cancel_all_jobs = lambda: (_ for _ in ()).throw(
        AssertionError("jobs should not be cancelled when pause audit fails")
    )
    app.show_worker_input_screen = lambda: (_ for _ in ()).throw(
        AssertionError("worker screen should not be shown when pause audit fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.change_worker()

    assert app.worker_name == "홍길동"
    assert app.current_tray.master_label_code == "ACTIVE"
    assert errors[0][0] == "작업 중지 기록 실패"


def test_change_worker_preserves_replacement_state_when_cancel_log_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession()
    app.master_label_replace_state = "awaiting_new_replacement"
    app.replacement_context = {"old_label": "OLD"}
    app._log_event = lambda *args, **kwargs: False
    app._cancel_all_jobs = lambda: (_ for _ in ()).throw(
        AssertionError("jobs should not be cancelled when replacement cancel audit fails")
    )
    app.show_worker_input_screen = lambda: (_ for _ in ()).throw(
        AssertionError("worker screen should not be shown when replacement cancel audit fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.change_worker()

    assert app.worker_name == "홍길동"
    assert app.master_label_replace_state == "awaiting_new_replacement"
    assert app.replacement_context == {"old_label": "OLD"}
    assert errors[0][0] == "교체 취소 기록 실패"


def test_change_worker_logs_partial_exchange_cancel_before_logout(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession()
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        target_quantity=1,
        defective_barcodes=["AAA2270730100-BAD-1"],
    )
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False, **kwargs: logged.append(
        {"event": event, "detail": {**(detail or {}), **kwargs}, "synchronous": synchronous}
    ) or True
    app._cancel_all_jobs = lambda: setattr(app, "cancelled", True)
    app.show_worker_input_screen = lambda: setattr(app, "showed_login", True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)

    app.change_worker()

    assert app.worker_name == ""
    assert logged[0]["event"] == "PRODUCT_EXCHANGE_CANCELLED"
    assert logged[0]["synchronous"] is True
    assert logged[0]["detail"]["reason"] == "worker_change"
    assert app.current_exchange_session.current_step == "not_started"
    assert app.cancelled is True
    assert app.showed_login is True


def test_change_worker_preserves_partial_exchange_when_cancel_log_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession()
    app.master_label_replace_state = None
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        target_quantity=1,
        defective_barcodes=["AAA2270730100-BAD-1"],
    )
    app._log_event = lambda *args, **kwargs: False
    app._cancel_all_jobs = lambda: (_ for _ in ()).throw(
        AssertionError("jobs should not be cancelled when exchange cancel audit fails")
    )
    app.show_worker_input_screen = lambda: (_ for _ in ()).throw(
        AssertionError("worker screen should not be shown when exchange cancel audit fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.change_worker()

    assert app.worker_name == "홍길동"
    assert app.current_exchange_session.defective_barcodes == ["AAA2270730100-BAD-1"]
    assert errors[0][0] == "교환 취소 기록 실패"


def test_on_closing_keeps_app_open_when_requested_state_save_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app._save_current_tray_state = lambda: False
    app._delete_current_tray_state = lambda: setattr(app, "state_deleted", True)
    app._log_event = lambda *args, **kwargs: setattr(app, "logged", True)
    app.errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: app.errors.append(args))

    app.on_closing()

    assert not hasattr(app, "state_deleted")
    assert not hasattr(app, "logged")
    assert app.errors


def test_on_closing_logs_discard_when_operator_declines_save(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(
        master_label_code="ACTIVE",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=["BC-1", "BC-2"],
    )
    app.deleted = False
    app.destroyed = False
    app.cancelled = False
    app.log_queue = queue.Queue()
    app.log_thread = type("DummyThread", (), {"is_alive": lambda self: False})()
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app._delete_current_tray_state = lambda: setattr(app, "deleted", True) or True
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: setattr(app, "cancelled", True)
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: False)
    monkeypatch.setattr(container_audit_module.pygame, "quit", lambda: None)

    app.on_closing()

    assert app.deleted is True
    assert app.destroyed is True
    assert logged[0]["event"] == "TRAY_DISCARDED_BY_OPERATOR"
    assert logged[0]["synchronous"] is True
    assert logged[0]["detail"]["reason"] == "close_without_saving"
    assert logged[0]["detail"]["scan_count"] == 2
    assert logged[1]["event"] == "WORK_END"
    assert logged[1]["synchronous"] is True


def test_on_closing_keeps_app_open_when_discard_log_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app._delete_current_tray_state = lambda: (_ for _ in ()).throw(
        AssertionError("current state should not be deleted when discard log fails")
    )
    app._log_event = lambda *args, **kwargs: False
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: False)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.on_closing()

    assert not hasattr(app, "destroyed")
    assert errors
    assert errors[0][0] == "작업 기록 실패"


def test_on_closing_keeps_app_open_when_discard_state_delete_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100")
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app._delete_current_tray_state = lambda: False
    app._log_event = lambda *args, **kwargs: True
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: False)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.on_closing()

    assert not hasattr(app, "destroyed")
    assert errors
    assert errors[0][0] == "작업 삭제 실패"


def test_on_closing_preserves_unclaimed_current_state_on_login_screen(monkeypatch):
    app = _headless_app()
    app.worker_name = ""
    app.current_tray = TraySession()
    app.destroyed = False
    app.cancelled = False
    app.log_queue = queue.Queue()
    app.log_thread = type("DummyThread", (), {"is_alive": lambda self: False})()
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app._delete_current_tray_state = lambda: setattr(app, "state_deleted", True)
    app._log_event = lambda *args, **kwargs: setattr(app, "logged", True)
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: setattr(app, "cancelled", True)
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.pygame, "quit", lambda: None)

    app.on_closing()

    assert not hasattr(app, "state_deleted")
    assert not hasattr(app, "logged")
    assert app.cancelled is True
    assert app.destroyed is True


def test_on_closing_logs_partial_exchange_cancel_before_shutdown(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession()
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD-1"],
    )
    app.destroyed = False
    app.cancelled = False
    app.log_queue = queue.Queue()
    app.log_thread = type("DummyThread", (), {"is_alive": lambda self: False})()
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda dialog: setattr(app, "exchange_destroyed", True)})()
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: setattr(app, "cancelled", True)
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.pygame, "quit", lambda: None)

    app.on_closing()

    assert [entry["event"] for entry in logged] == ["PRODUCT_EXCHANGE_CANCELLED", "WORK_END"]
    assert logged[0]["synchronous"] is True
    assert logged[0]["detail"]["reason"] == "app_close"
    assert logged[0]["detail"]["defective_barcodes"] == ["AAA2270730100-BAD-1"]
    assert app.current_exchange_session.current_step == "not_started"
    assert app.destroyed is True


def test_on_closing_keeps_app_open_when_exchange_cancel_log_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession()
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD-1"],
    )
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app._log_event = lambda *args, **kwargs: False
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.on_closing()

    assert not hasattr(app, "destroyed")
    assert app.current_exchange_session.defective_barcodes == ["AAA2270730100-BAD-1"]
    assert errors[0][0] == "교환 취소 기록 실패"


def test_on_closing_logs_replacement_cancel_before_shutdown(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession()
    app.current_exchange_session = ProductExchangeSession()
    app.master_label_replace_state = "awaiting_new_replacement"
    app.replacement_context = {"old_label": "OLD"}
    app.destroyed = False
    app.log_queue = queue.Queue()
    app.log_thread = type("DummyThread", (), {"is_alive": lambda self: False})()
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app.save_settings = lambda: None
    app._cancel_all_jobs = lambda: None
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.pygame, "quit", lambda: None)

    app.on_closing()

    assert [entry["event"] for entry in logged] == ["HISTORICAL_REPLACE_CANCEL", "WORK_END"]
    assert logged[0]["detail"]["reason"] == "app_close"
    assert logged[0]["synchronous"] is True
    assert app.master_label_replace_state is None
    assert app.replacement_context == {}
    assert app.destroyed is True


def test_on_closing_keeps_app_open_when_replacement_cancel_log_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession()
    app.current_exchange_session = ProductExchangeSession()
    app.master_label_replace_state = "awaiting_new_replacement"
    app.replacement_context = {"old_label": "OLD"}
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app._log_event = lambda *args, **kwargs: False
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.on_closing()

    assert not hasattr(app, "destroyed")
    assert app.master_label_replace_state == "awaiting_new_replacement"
    assert app.replacement_context == {"old_label": "OLD"}
    assert errors[0][0] == "교체 취소 기록 실패"


def test_on_closing_keeps_app_open_when_work_end_log_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession()
    app.current_exchange_session = ProductExchangeSession()
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app._log_event = lambda *args, **kwargs: False
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.on_closing()

    assert not hasattr(app, "destroyed")
    assert errors[0][0] == "작업 종료 기록 실패"


def test_on_closing_restores_current_state_when_work_end_log_fails_after_discard(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.current_tray = TraySession(
        master_label_code="ACTIVE",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=["AAA2270730100-001"],
    )
    (tmp_path / "current.json").write_text("stale", encoding="utf-8")
    app.root = type("DummyRoot", (), {"destroy": lambda root: setattr(app, "destroyed", True)})()
    app._log_event = lambda event, detail=None, synchronous=False: event != "WORK_END"
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askokcancel", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: False)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.on_closing()

    assert not hasattr(app, "destroyed")
    restored = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert restored["master_label_code"] == "ACTIVE"
    assert restored["scanned_barcodes"] == ["AAA2270730100-001"]
    assert errors[0][0] == "작업 종료 기록 실패"
    assert "복구했습니다" in errors[0][1]


def test_mismatch_scan_saves_dirty_current_tray_state(tmp_path):
    app = _headless_app()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=[],
        scan_times=[],
        tray_size=60,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.master_label_replace_state = None
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app.COLOR_DANGER = "danger"
    app.show_fullscreen_warning = lambda *args, **kwargs: None
    app._log_event = lambda *args, **kwargs: True

    app._process_barcode_logic("DIFFERENT-PRODUCT-BARCODE")

    saved_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert saved_state["mismatch_error_count"] == 1
    assert saved_state["has_error_or_reset"] is True


def test_product_scan_rejects_when_tray_is_already_full():
    app = _headless_app()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=1",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["AAA2270730100-001"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=1,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    app.master_label_replace_state = None
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 2, 0)
    app.COLOR_DANGER = "danger"
    app.logged = []
    app.show_fullscreen_warning = lambda *args, **kwargs: setattr(app, "warning", args)
    app._log_event = lambda *args, **kwargs: app.logged.append((args, kwargs)) or True
    app._save_current_tray_state = lambda: setattr(app, "saved", True)
    app.complete_tray = lambda: (_ for _ in ()).throw(AssertionError("full tray overscan should not complete"))

    app._process_barcode_logic("AAA2270730100-002")

    assert app.current_tray.scanned_barcodes == ["AAA2270730100-001"]
    assert app.warning[0] == "트레이 수량 초과"
    assert app.logged[0][0][0] == "SCAN_FAIL_TRAY_FULL"
    assert app.logged[0][1]["detail"]["tray_capacity"] == 1
    assert app.saved is True


def test_process_barcode_rejects_completed_master_label_by_canonical_identity(tmp_path):
    app = _headless_app()
    app.current_tray = TraySession()
    app.completed_master_labels = set()
    app._remember_completed_master_label('{"QT":"2","CLC":"AAA2270730100"}')
    app.master_label_replace_state = None
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app.warning = None
    app.show_fullscreen_warning = lambda *args, **kwargs: setattr(app, "warning", args)

    app._process_barcode_logic('{"CLC":"AAA2270730100","QT":"2"}')

    assert app.current_tray.master_label_code == ""
    assert app.warning[0] == "현품표 중복"


def test_process_barcode_routes_internal_test_log_command():
    app = _headless_app()
    app.internal_test_commands_enabled = True
    app.master_label_replace_state = None
    app._update_last_activity_time = lambda: setattr(app, "activity_updated", True)
    app._generate_test_logs = lambda count: setattr(app, "generated_count", count)

    app._process_barcode_logic("TEST_LOG_3")

    assert app.activity_updated is True
    assert app.generated_count == 3


def test_process_barcode_treats_internal_test_command_as_normal_scan_by_default():
    app = _headless_app()
    app.master_label_replace_state = None
    app.current_tray = TraySession()
    app.ITEM_CODE_LENGTH = 13
    app._update_last_activity_time = lambda: setattr(app, "activity_updated", True)
    app._generate_test_logs = lambda count: (_ for _ in ()).throw(
        AssertionError("internal test command should be gated off by default")
    )
    app.warning = None
    app.show_fullscreen_warning = lambda *args, **kwargs: setattr(app, "warning", args)

    app._process_barcode_logic("TEST_LOG_3")

    assert app.activity_updated is True
    assert app.warning[0] == "작업 시작 오류"
    assert not hasattr(app, "generated_count")


def test_process_barcode_runs_delayed_scan_when_epoch_is_current():
    app = _headless_app()
    app.root = CapturingRoot()
    app.scan_entry = DummyScanEntry("AAA2270730100-001")
    app._scan_callback_epoch = 0
    processed = []
    app._process_barcode_logic = lambda raw_barcode: processed.append(raw_barcode)

    app.process_barcode()
    callback, args = app.root.calls[0]
    callback(*args)

    assert app.scan_entry.deleted is True
    assert processed == ["AAA2270730100-001"]


def test_process_barcode_discards_delayed_scan_after_session_epoch_changes():
    app = _headless_app()
    app.root = CapturingRoot()
    app.scan_entry = DummyScanEntry("AAA2270730100-001")
    app._scan_callback_epoch = 0
    processed = []
    app._process_barcode_logic = lambda raw_barcode: processed.append(raw_barcode)

    app.process_barcode()
    app._invalidate_pending_scan_callbacks()
    callback, args = app.root.calls[0]
    callback(*args)

    assert app.scan_entry.deleted is True
    assert processed == []


def test_initiate_replacement_invalidates_pending_main_scan_before_replacement_mode(monkeypatch):
    app = _headless_app()
    app.root = CapturingRoot()
    app.scan_entry = DummyScanEntry("PHS=1|CLC=AAA2270730100|QT=1")
    app._scan_callback_epoch = 0
    app.current_tray = TraySession()
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.COLOR_PRIMARY = "primary"
    processed = []
    logged = []
    app._process_barcode_logic = lambda raw_barcode: processed.append(raw_barcode)
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    app.show_status_message = lambda *args, **kwargs: None
    app._update_current_item_label = lambda: None
    app._schedule_focus_return = lambda: None

    app.process_barcode()
    app.initiate_master_label_replacement()
    callback, args = app.root.calls[0]
    callback(*args)

    assert processed == []
    assert app.master_label_replace_state == "awaiting_old_completed"
    assert app.replacement_context == {}
    assert logged == [{"event": "HISTORICAL_REPLACE_START", "detail": None, "synchronous": True}]


def test_initiate_replacement_keeps_state_when_start_audit_fails(monkeypatch):
    app = _headless_app()
    app.current_tray = TraySession()
    app.master_label_replace_state = None
    app.replacement_context = {}
    app._scan_callback_epoch = 3
    app._log_event = lambda *args, **kwargs: False
    app._invalidate_pending_scan_callbacks = lambda: (_ for _ in ()).throw(
        AssertionError("callbacks should not be invalidated when replacement start audit fails")
    )
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("status should not show when replacement start audit fails")
    )
    app._update_current_item_label = lambda: (_ for _ in ()).throw(
        AssertionError("item label should not update when replacement start audit fails")
    )
    app._schedule_focus_return = lambda: (_ for _ in ()).throw(
        AssertionError("focus should not be scheduled when replacement start audit fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.initiate_master_label_replacement()

    assert app.master_label_replace_state is None
    assert app.replacement_context == {}
    assert app._scan_callback_epoch == 3
    assert errors
    assert errors[0][0] == "교체 시작 기록 실패"


def test_show_exchange_dialog_invalidates_pending_main_scan_when_reusing_dialog(monkeypatch):
    app = _headless_app()
    app.root = CapturingRoot()
    app.scan_entry = DummyScanEntry("AAA2270730100-001")
    app._scan_callback_epoch = 0
    app.current_tray = TraySession()
    app.current_exchange_session = ProductExchangeSession(defective_barcodes=["AAA2270730100-BAD-1"])
    processed = []
    app._process_barcode_logic = lambda raw_barcode: processed.append(raw_barcode)

    class ExistingDialog:
        def __init__(self):
            self.calls = []

        def winfo_exists(self):
            return True

        def lift(self):
            self.calls.append("lift")

        def focus_force(self):
            self.calls.append("focus_force")

    dialog = ExistingDialog()
    app.exchange_dialog = dialog
    monkeypatch.setattr(
        container_audit_module.tk,
        "Toplevel",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("existing exchange dialog should be reused")),
    )

    app.process_barcode()
    app.show_exchange_dialog()
    callback, args = app.root.calls[0]
    callback(*args)

    assert processed == []
    assert dialog.calls == ["lift", "focus_force"]


def test_delayed_scan_highlight_reset_targets_original_row_after_newer_scan():
    app = _headless_app()
    app.root = CapturingRoot()
    app.current_tray = TraySession(master_label_code="ACTIVE")
    app.scanned_listbox = CapturingListbox()
    app.undo_button = {"state": container_audit_module.tk.DISABLED}
    app.COLOR_SUCCESS = "success"
    app.COLOR_SIDEBAR_BG = "sidebar"
    app.COLOR_TEXT = "text"
    app._scan_callback_epoch = 0
    app.success_sound = None
    app._update_center_display = lambda: None
    app._update_current_item_label = lambda: None
    app._log_event = lambda *args, **kwargs: True

    app.add_scanned_barcode("AAA2270730100-001", datetime.datetime(2026, 6, 22, 9, 1, 0), 0.0)
    callback, args = app.root.calls[0]
    app.scanned_listbox.insert(0, "(2) AAA2270730100-002")

    callback(*args)

    assert app.scanned_listbox.configs[0] == (0, {"bg": "success", "fg": "white"})
    assert app.scanned_listbox.configs[1] == (1, {"bg": "sidebar", "fg": "text"})


def test_delayed_scan_highlight_reset_ignores_stale_epoch():
    app = _headless_app()
    app.root = CapturingRoot()
    app.current_tray = TraySession(master_label_code="ACTIVE")
    app.scanned_listbox = CapturingListbox()
    app.undo_button = {"state": container_audit_module.tk.DISABLED}
    app.COLOR_SUCCESS = "success"
    app.COLOR_SIDEBAR_BG = "sidebar"
    app.COLOR_TEXT = "text"
    app._scan_callback_epoch = 0
    app.success_sound = None
    app._update_center_display = lambda: None
    app._update_current_item_label = lambda: None
    app._log_event = lambda *args, **kwargs: True

    app.add_scanned_barcode("AAA2270730100-001", datetime.datetime(2026, 6, 22, 9, 1, 0), 0.0)
    app._invalidate_pending_scan_callbacks()
    callback, args = app.root.calls[0]

    callback(*args)

    assert app.scanned_listbox.configs == [(0, {"bg": "success", "fg": "white"})]


def test_undo_last_scan_rolls_back_memory_and_ui_when_state_save_fails():
    app = _headless_app()
    scan_time_1 = datetime.datetime(2026, 6, 22, 9, 1, 0)
    scan_time_2 = datetime.datetime(2026, 6, 22, 9, 2, 0)
    app.current_tray = TraySession(
        master_label_code="ACTIVE",
        scanned_barcodes=["BC-1", "BC-2"],
        scan_times=[scan_time_1, scan_time_2],
    )
    app.scanned_listbox = CapturingListbox()
    app.scanned_listbox.rows = ["(2) BC-2", "(1) BC-1"]
    app.undo_button = {"state": "normal"}
    app.COLOR_SUCCESS = "success"
    app.COLOR_DANGER = "danger"
    app._update_last_activity_time = lambda: setattr(app, "activity_updated", True)
    app._save_current_tray_state = lambda: False
    app._update_center_display = lambda: setattr(app, "center_updated", True)
    app._update_current_item_label = lambda: setattr(app, "item_label_updated", True)
    app._schedule_focus_return = lambda: setattr(app, "focus_scheduled", True)
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("undo event should not be logged when durable state save fails")
    )
    messages = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)

    app.undo_last_scan()

    assert app.activity_updated is True
    assert app.current_tray.scanned_barcodes == ["BC-1", "BC-2"]
    assert app.current_tray.scan_times == [scan_time_1, scan_time_2]
    assert app.scanned_listbox.rows == ["(2) BC-2", "(1) BC-1"]
    assert app.undo_button["state"] == "normal"
    assert app.center_updated is True
    assert app.item_label_updated is True
    assert app.focus_scheduled is True
    assert messages[0][0].startswith("스캔 취소 상태 저장에 실패")


def test_undo_last_scan_saves_before_logging_success_and_disables_at_zero():
    app = _headless_app()
    scan_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app.current_tray = TraySession(
        master_label_code="ACTIVE",
        scanned_barcodes=["BC-1"],
        scan_times=[scan_time],
    )
    app.scanned_listbox = CapturingListbox()
    app.scanned_listbox.rows = ["(1) BC-1"]
    app.undo_button = {"state": "normal"}
    app.COLOR_DANGER = "danger"
    app._update_last_activity_time = lambda: None
    saved = []
    app._save_current_tray_state = lambda: saved.append(list(app.current_tray.scanned_barcodes)) or True
    app._update_center_display = lambda: None
    app._update_current_item_label = lambda: None
    app._schedule_focus_return = lambda: None
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "saved_before_log": list(saved), "synchronous": synchronous}
    ) or True
    app.show_status_message = lambda *args, **kwargs: None

    app.undo_last_scan()

    assert saved == [[]]
    assert logged == [
        {"event": "SCAN_UNDO", "detail": {"undone_barcode": "BC-1"}, "saved_before_log": [[]], "synchronous": True}
    ]
    assert app.current_tray.scanned_barcodes == []
    assert app.current_tray.scan_times == []
    assert app.scanned_listbox.rows == []
    assert app.undo_button["state"] == container_audit_module.tk.DISABLED


def test_undo_last_scan_restores_scan_when_undo_log_fails(monkeypatch):
    app = _headless_app()
    scan_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app.current_tray = TraySession(
        master_label_code="ACTIVE",
        scanned_barcodes=["BC-1"],
        scan_times=[scan_time],
    )
    app.scanned_listbox = CapturingListbox()
    app.scanned_listbox.rows = ["(1) BC-1"]
    app.undo_button = {"state": "normal"}
    app.COLOR_SUCCESS = "success"
    app.COLOR_DANGER = "danger"
    app._update_last_activity_time = lambda: None
    saved = []
    app._save_current_tray_state = lambda: saved.append(list(app.current_tray.scanned_barcodes)) or True
    app._update_center_display = lambda: setattr(app, "center_updated", True)
    app._update_current_item_label = lambda: setattr(app, "item_label_updated", True)
    app._schedule_focus_return = lambda: setattr(app, "focus_scheduled", True)
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) and False
    messages = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.undo_last_scan()

    assert saved == [[], ["BC-1"]]
    assert logged == [{"event": "SCAN_UNDO", "detail": {"undone_barcode": "BC-1"}, "synchronous": True}]
    assert app.current_tray.scanned_barcodes == ["BC-1"]
    assert app.current_tray.scan_times == [scan_time]
    assert app.scanned_listbox.rows == ["(1) BC-1"]
    assert app.undo_button["state"] == container_audit_module.tk.NORMAL
    assert app.center_updated is True
    assert app.item_label_updated is True
    assert app.focus_scheduled is True
    assert messages[0][0].startswith("스캔 취소 기록 저장에 실패")
    assert errors == []


def test_product_scan_rolls_back_when_state_save_fails():
    app = _headless_app()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=2",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=[],
        scan_times=[],
        tray_size=2,
    )
    app.master_label_replace_state = None
    app.ITEM_CODE_LENGTH = 13
    app.COLOR_SUCCESS = "success"
    app.COLOR_DANGER = "danger"
    app.success_sound = None
    app.root = CapturingRoot()
    app.scanned_listbox = CapturingListbox()
    app.undo_button = {"state": "disabled"}
    app._update_last_activity_time = lambda: None
    app._update_center_display = lambda: setattr(app, "center_updated", True)
    app._update_current_item_label = lambda: setattr(app, "item_label_updated", True)
    app._save_current_tray_state = lambda: False
    app.complete_tray = lambda: (_ for _ in ()).throw(
        AssertionError("failed product scan save should not complete the tray")
    )
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("SCAN_OK should not be logged when state save fails")
    )
    messages = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)

    app._process_barcode_logic("AAA2270730100-001")

    assert app.current_tray.scanned_barcodes == []
    assert app.current_tray.scan_times == []
    assert app.scanned_listbox.rows == []
    assert app.undo_button["state"] == container_audit_module.tk.DISABLED
    assert app.center_updated is True
    assert app.item_label_updated is True
    assert messages[0][0].startswith("스캔 상태 저장에 실패")


def test_product_scan_saves_before_logging_scan_ok():
    app = _headless_app()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=2",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=[],
        scan_times=[],
        tray_size=2,
    )
    app.master_label_replace_state = None
    app.ITEM_CODE_LENGTH = 13
    app.COLOR_SUCCESS = "success"
    app.success_sound = None
    app.root = CapturingRoot()
    app.scanned_listbox = CapturingListbox()
    app.undo_button = {"state": "disabled"}
    app._update_last_activity_time = lambda: None
    app._update_center_display = lambda: None
    app._update_current_item_label = lambda: None
    saved = []
    app._save_current_tray_state = lambda: saved.append(list(app.current_tray.scanned_barcodes)) or True
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "saved_before_log": list(saved), "detail": detail}
    ) or True
    app.complete_tray = lambda: setattr(app, "completed", True)

    app._process_barcode_logic("AAA2270730100-001")

    assert saved == [["AAA2270730100-001"]]
    assert logged[0]["event"] == "SCAN_OK"
    assert logged[0]["saved_before_log"] == [["AAA2270730100-001"]]
    assert app.current_tray.scanned_barcodes == ["AAA2270730100-001"]
    assert not hasattr(app, "completed")


def test_product_scan_clamps_clock_rollback_interval_before_scan_ok(monkeypatch):
    class FixedDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            value = datetime.datetime(2026, 6, 22, 9, 0, 0)
            return value if tz is None else value.replace(tzinfo=tz)

    app = _headless_app()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=3",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=["AAA2270730100-000"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=3,
    )
    app.master_label_replace_state = None
    app.ITEM_CODE_LENGTH = 13
    app.COLOR_SUCCESS = "success"
    app.success_sound = None
    app.root = CapturingRoot()
    app.scanned_listbox = CapturingListbox()
    app.undo_button = {"state": "disabled"}
    app._update_last_activity_time = lambda: None
    app._update_center_display = lambda: None
    app._update_current_item_label = lambda: None
    app._save_current_tray_state = lambda: True
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail}
    ) or True
    app.complete_tray = lambda: setattr(app, "completed", True)
    monkeypatch.setattr(container_audit_module.datetime, "datetime", FixedDateTime)

    app._process_barcode_logic("AAA2270730100-001")

    assert app.current_tray.scanned_barcodes == ["AAA2270730100-000", "AAA2270730100-001"]
    assert logged[0]["event"] == "SCAN_OK"
    assert logged[0]["detail"]["interval_sec"] == "0.00"
    assert not hasattr(app, "completed")


def test_product_scan_logs_format_failure_without_mutating_tray_state():
    app = _headless_app()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=2",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=[],
        scan_times=[],
        tray_size=2,
    )
    app.master_label_replace_state = None
    app.ITEM_CODE_LENGTH = 13
    app.COLOR_DANGER = "danger"
    app._update_last_activity_time = lambda: None
    app._save_current_tray_state = lambda: (_ for _ in ()).throw(
        AssertionError("format failure should not mutate or save tray state")
    )
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail}
    ) or True
    app.show_fullscreen_warning = lambda *args, **kwargs: setattr(app, "warning", args)

    app._process_barcode_logic("AAA2270730100")

    assert app.current_tray.scanned_barcodes == []
    assert app.current_tray.mismatch_error_count == 0
    assert app.current_tray.has_error_or_reset is False
    assert logged == [
        {
            "event": "SCAN_FAIL_FORMAT",
            "detail": {
                "raw_barcode": "AAA2270730100",
                "reason": "barcode_too_short",
                "item_code_length": 13,
            },
        }
    ]
    assert app.warning[0] == "바코드 형식 오류"


def test_product_scan_rejects_barcode_matching_multiple_item_codes():
    app = _headless_app()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=2",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=[],
        scan_times=[],
        tray_size=2,
    )
    app.master_label_replace_state = None
    app.ITEM_CODE_LENGTH = 13
    app.COLOR_DANGER = "danger"
    app.items_data = [
        {"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"},
        {"Item Code": "BBB2270730100", "Item Name": "other item", "Spec": "other spec"},
    ]
    app._update_last_activity_time = lambda: None
    saved = []
    app._save_current_tray_state = lambda: saved.append(
        {
            "mismatch_error_count": app.current_tray.mismatch_error_count,
            "has_error_or_reset": app.current_tray.has_error_or_reset,
        }
    ) or True
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail}
    ) or True
    app.show_fullscreen_warning = lambda *args, **kwargs: setattr(app, "warning", args)
    app.add_scanned_barcode = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("ambiguous product barcode should not be accepted")
    )

    app._process_barcode_logic("AAA2270730100-BBB2270730100-001")

    assert app.current_tray.scanned_barcodes == []
    assert app.current_tray.mismatch_error_count == 1
    assert app.current_tray.has_error_or_reset is True
    assert saved == [{"mismatch_error_count": 1, "has_error_or_reset": True}]
    assert logged == [
        {
            "event": "SCAN_FAIL_AMBIGUOUS_ITEM_CODE",
            "detail": {
                "expected": "AAA2270730100",
                "scanned": "AAA2270730100-BBB2270730100-001",
                "matching_item_codes": ["AAA2270730100", "BBB2270730100"],
            },
        }
    ]
    assert app.warning[0] == "품목 코드 모호"


def test_product_scan_rejects_catalog_resolved_different_overlapping_item_code():
    app = _headless_app()
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA227073|QT=2",
        item_code="AAA227073",
        item_name="short item",
        scanned_barcodes=[],
        scan_times=[],
        tray_size=2,
    )
    app.master_label_replace_state = None
    app.ITEM_CODE_LENGTH = 9
    app.COLOR_DANGER = "danger"
    app.items_data = [
        {"Item Code": "AAA227073", "Item Name": "short item", "Spec": "short spec"},
        {"Item Code": "AAA2270730100", "Item Name": "long item", "Spec": "long spec"},
    ]
    app._update_last_activity_time = lambda: None
    saved = []
    app._save_current_tray_state = lambda: saved.append(
        {
            "mismatch_error_count": app.current_tray.mismatch_error_count,
            "has_error_or_reset": app.current_tray.has_error_or_reset,
        }
    ) or True
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail}
    ) or True
    app.show_fullscreen_warning = lambda *args, **kwargs: setattr(app, "warning", args)
    app.add_scanned_barcode = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("overlapping longer catalog item should not be accepted")
    )

    app._process_barcode_logic("PREFIX-AAA2270730100-SUFFIX")

    assert app.current_tray.scanned_barcodes == []
    assert app.current_tray.mismatch_error_count == 1
    assert app.current_tray.has_error_or_reset is True
    assert saved == [{"mismatch_error_count": 1, "has_error_or_reset": True}]
    assert logged == [
        {
            "event": "SCAN_FAIL_MISMATCH",
            "detail": {
                "expected": "AAA227073",
                "scanned": "PREFIX-AAA2270730100-SUFFIX",
                "matched_item_code": "AAA2270730100",
            },
        }
    ]
    assert app.warning[0] == "품목 코드 불일치!"


def test_reset_current_work_preserves_active_tray_when_reset_log_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100", scanned_barcodes=["BC-1"])
    app.scanned_listbox = DummyListbox()
    app.COLOR_DANGER = "danger"
    app._update_last_activity_time = lambda: setattr(app, "activity_updated", True)
    app._log_event = lambda *args, **kwargs: False
    assert app._save_current_tray_state() is True
    app._stop_stopwatch = lambda: (_ for _ in ()).throw(
        AssertionError("stopwatch should not stop when reset log fails")
    )
    messages = []
    errors = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.reset_current_work()

    assert app.activity_updated is True
    assert app.current_tray.master_label_code == "ACTIVE"
    assert app.scanned_listbox.deleted is False
    restored_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert restored_state["master_label_code"] == "ACTIVE"
    assert errors
    assert messages[0][0].startswith("초기화 기록 저장에 실패")


def test_reset_current_work_preserves_active_tray_when_state_delete_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100", scanned_barcodes=["BC-1"])
    app.scanned_listbox = DummyListbox()
    app.COLOR_DANGER = "danger"
    app._update_last_activity_time = lambda: None
    app._delete_current_tray_state = lambda: False
    app._stop_stopwatch = lambda: (_ for _ in ()).throw(
        AssertionError("stopwatch should not stop when state delete fails")
    )
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    messages = []
    errors = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app.reset_current_work()

    assert logged == [
        {
            "event": "TRAY_RESET_STATE_DELETE_FAILED",
            "detail": {"master_label_code": "ACTIVE", "scan_count_at_reset": 1},
            "synchronous": False,
        }
    ]
    assert app.current_tray.master_label_code == "ACTIVE"
    assert app.scanned_listbox.deleted is False
    assert errors
    assert messages[0][0].startswith("현재 작업 상태 파일 삭제에 실패")


def test_reset_current_work_logs_sync_and_clears_after_state_delete(monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="AAA2270730100", scanned_barcodes=["BC-1"])
    app.scanned_listbox = DummyListbox()
    app.undo_button = {"state": "normal"}
    app.COLOR_DANGER = "danger"
    app._update_last_activity_time = lambda: None
    app._delete_current_tray_state = lambda: True
    app._stop_stopwatch = lambda: setattr(app, "stopwatch_stopped", True)
    app._stop_idle_checker = lambda: setattr(app, "idle_stopped", True)
    app._invalidate_pending_scan_callbacks = lambda: setattr(app, "callbacks_invalidated", True)
    app._update_all_summaries = lambda: setattr(app, "summaries_updated", True)
    app._reset_ui_to_waiting_state = lambda: setattr(app, "ui_reset", True)
    app._schedule_focus_return = lambda: setattr(app, "focus_scheduled", True)
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    app.show_status_message = lambda *args, **kwargs: setattr(app, "status_message", args)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)

    app.reset_current_work()

    assert logged == [
        {
            "event": "TRAY_RESET",
            "detail": {"master_label_code": "ACTIVE", "scan_count_at_reset": 1},
            "synchronous": True,
        }
    ]
    assert app.current_tray.master_label_code == ""
    assert app.scanned_listbox.deleted is True
    assert app.undo_button["state"] == container_audit_module.tk.DISABLED
    assert app.stopwatch_stopped is True
    assert app.idle_stopped is True
    assert app.callbacks_invalidated is True
    assert app.summaries_updated is True
    assert app.ui_reset is True
    assert app.focus_scheduled is True


def test_process_barcode_rejects_non_positive_qr_quantity(tmp_path):
    app = _headless_app()
    app.current_tray = TraySession()
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app.warning = None
    app.show_fullscreen_warning = lambda *args, **kwargs: setattr(app, "warning", args)

    app._process_barcode_logic('{"CLC":"AAA2270730100","QT":"0"}')

    assert app.current_tray.master_label_code == ""
    assert app.warning[0] == "QR코드 오류"


def test_process_barcode_starts_tray_from_json_master_label(tmp_path):
    app = _headless_app()
    app.current_tray = TraySession()
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.show_tray_image_var = DummyToggle()
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app.logged = []
    app._log_event = lambda *args, **kwargs: app.logged.append((args, kwargs)) or True
    app._update_tray_image_display = lambda: None
    app._update_current_item_label = lambda: None
    app._update_center_display = lambda: None
    app._start_stopwatch = lambda: None
    saved_start_times = []
    app._save_current_tray_state = lambda: saved_start_times.append(app.current_tray.start_time) or True
    app.show_fullscreen_warning = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("valid JSON master label should not warn")
    )

    app._process_barcode_logic('{"CLC":"AAA2270730100","QT":"2"}')

    assert app.current_tray.master_label_code == '{"CLC":"AAA2270730100","QT":"2"}'
    assert app.current_tray.item_code == "AAA2270730100"
    assert app.current_tray.tray_size == 2
    assert isinstance(saved_start_times[0], datetime.datetime)
    assert app.show_tray_image_var.value is True
    assert app.logged[0][0][0] == "MASTER_LABEL_SCANNED_NEW"
    assert app.logged[0][1] == {"detail": {"CLC": "AAA2270730100", "QT": "2"}, "synchronous": True}


def test_process_barcode_blocks_same_label_parked_by_other_worker(tmp_path, monkeypatch):
    app = _headless_app()
    app.current_tray = TraySession()
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app.worker_name = "새작업자"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.COLOR_DANGER = "danger"
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("duplicate parked label should not start a tray event")
    )
    app._save_current_tray_state = lambda: (_ for _ in ()).throw(
        AssertionError("duplicate parked label should not save active state")
    )
    app._start_stopwatch = lambda: (_ for _ in ()).throw(
        AssertionError("duplicate parked label should not start stopwatch")
    )
    warnings = []
    app.show_fullscreen_warning = lambda *args, **kwargs: warnings.append(args)
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesno",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("restore prompt should not open")),
    )
    label = "PHS=1|CLC=AAA2270730100|QT=2"
    parked_session = TraySession(
        master_label_code=label,
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["AAA2270730100-001"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=2,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    parked_tray_store.ParkedTrayStore(app.parked_trays_dir).save_state(
        tray_state.tray_session_to_state(parked_session, worker_name="이전작업자"),
        worker_name="이전작업자",
        master_label=label,
    )

    app._process_barcode_logic(label)

    assert app.current_tray.master_label_code == ""
    assert warnings[0][0] == "보류 작업 중복"
    assert "이전작업자" in warnings[0][1]


def test_process_barcode_keeps_empty_tray_when_master_label_state_save_fails(tmp_path):
    app = _headless_app()
    app.current_tray = TraySession()
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.show_tray_image_var = DummyToggle()
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app.COLOR_DANGER = "danger"
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("master label event should not be logged when state save fails")
    )
    app._update_tray_image_display = lambda: (_ for _ in ()).throw(
        AssertionError("image display should not update when state save fails")
    )
    app._update_current_item_label = lambda: (_ for _ in ()).throw(
        AssertionError("item label should not update when state save fails")
    )
    app._update_center_display = lambda: (_ for _ in ()).throw(
        AssertionError("center display should not update when state save fails")
    )
    app._start_stopwatch = lambda: (_ for _ in ()).throw(
        AssertionError("stopwatch should not start when state save fails")
    )
    app._save_current_tray_state = lambda: False
    messages = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)
    app.show_fullscreen_warning = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("valid JSON master label should not warn")
    )

    app._process_barcode_logic('{"CLC":"AAA2270730100","QT":"2"}')

    assert app.current_tray.master_label_code == ""
    assert app.show_tray_image_var.value is None
    assert messages[0][0].startswith("현품표 상태 저장에 실패")


def test_process_barcode_rolls_back_state_when_master_label_audit_log_fails(tmp_path):
    app = _headless_app()
    app.current_tray = TraySession()
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.show_tray_image_var = DummyToggle()
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app.COLOR_DANGER = "danger"
    app._log_event = lambda *args, **kwargs: False
    app._update_tray_image_display = lambda: (_ for _ in ()).throw(
        AssertionError("image display should not update when audit log fails")
    )
    app._update_current_item_label = lambda: (_ for _ in ()).throw(
        AssertionError("item label should not update when audit log fails")
    )
    app._update_center_display = lambda: (_ for _ in ()).throw(
        AssertionError("center display should not update when audit log fails")
    )
    app._start_stopwatch = lambda: (_ for _ in ()).throw(
        AssertionError("stopwatch should not start when audit log fails")
    )
    messages = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)
    app.show_fullscreen_warning = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("valid JSON master label should not warn")
    )

    app._process_barcode_logic('{"CLC":"AAA2270730100","QT":"2"}')

    assert app.current_tray.master_label_code == ""
    assert not (tmp_path / "current.json").exists()
    assert app.show_tray_image_var.value is None
    assert messages[0][0].startswith("현품표 시작 기록 저장에 실패")


def test_process_barcode_starts_tray_from_base64_encoded_json_master_label(tmp_path):
    app = _headless_app()
    app.current_tray = TraySession()
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.show_tray_image_var = DummyToggle()
    app.is_idle = False
    app.last_activity_time = datetime.datetime(2026, 6, 22, 9, 1, 0)
    app._log_event = lambda *args, **kwargs: True
    app._update_tray_image_display = lambda: None
    app._update_current_item_label = lambda: None
    app._update_center_display = lambda: None
    app._start_stopwatch = lambda: None
    app._save_current_tray_state = lambda: True
    app.show_fullscreen_warning = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("valid base64 JSON master label should not warn")
    )
    encoded = base64.b64encode(b'{"CLC":"AAA2270730100","QT":"2"}').decode("ascii")

    app._process_barcode_logic(encoded)

    assert app.current_tray.master_label_code == '{"CLC":"AAA2270730100","QT":"2"}'
    assert app.current_tray.item_code == "AAA2270730100"


def test_complete_tray_writes_enriched_csv_before_resetting_state(tmp_path):
    app = _completion_app(tmp_path)

    app.complete_tray()

    with open(app.log_file_path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["event"] == "TRAY_COMPLETE"
    details = json.loads(rows[0]["details"])
    assert details["source_system"] == "container_audit"
    assert details["source_transport_or_dataset"] == "legacy_transfer_csv"
    assert details["dispatch_key"] == "container_audit|legacy_transfer_csv|TRAY_COMPLETE"
    assert details["product_barcodes"] == ["BC-1", "BC-2"]
    assert details["quantity_basis"] == "PRODUCT_BARCODE"
    assert details["master_label_fields"]["CLC"] == "AAA2270730100"
    assert details["item_spec"] == "fixture spec"
    assert details["spec"] == "fixture spec"
    assert app.current_tray.master_label_code == ""
    assert app.state_deleted is True
    assert app.scanned_listbox.deleted is True
    assert app.undo_button["state"] == container_audit_module.tk.DISABLED
    assert app.stopwatch_stopped is True
    assert app.idle_stopped is True


def test_complete_tray_uses_payload_builder_for_json_master_label(tmp_path):
    app = _completion_app(tmp_path)
    app.current_tray.master_label_code = '{"CLC":"AAA2270730100","QT":"60"}'

    app.complete_tray()

    with open(app.log_file_path, newline="", encoding="utf-8-sig") as f:
        row = next(csv.DictReader(f))
    details = json.loads(row["details"])
    assert details["master_label_fields"] == {"CLC": "AAA2270730100", "QT": "60"}


def test_complete_tray_still_resets_when_best_time_update_fails(tmp_path):
    app = _completion_app(tmp_path)
    app.current_tray.has_error_or_reset = False
    app.current_tray.scanned_barcodes = [f"AAA2270730100-{index:03d}" for index in range(60)]
    app.current_tray.scan_times = [
        datetime.datetime(2026, 6, 22, 9, 0, 0) + datetime.timedelta(seconds=index)
        for index in range(60)
    ]
    app.current_tray.stopwatch_seconds = 300.0
    app._update_best_time_records = lambda work_time: (_ for _ in ()).throw(RuntimeError("best time unavailable"))

    app.complete_tray()

    assert app.completed_tray_times == [300.0]
    assert app.total_tray_count == 1
    assert app.current_tray.master_label_code == ""
    assert app.state_deleted is True
    assert app.scanned_listbox.deleted is True
    assert app.summaries_updated is True
    assert app.ui_reset is True


@pytest.mark.parametrize(
    ("work_time", "expected_updates"),
    [
        (120.0, []),
        (300.0, [300.0]),
    ],
)
def test_complete_tray_matches_reload_time_best_time_eligibility(tmp_path, work_time, expected_updates):
    app = _completion_app(tmp_path)
    app.current_tray.has_error_or_reset = False
    app.current_tray.scanned_barcodes = [f"AAA2270730100-{index:03d}" for index in range(60)]
    app.current_tray.scan_times = [
        datetime.datetime(2026, 6, 22, 9, 0, 0) + datetime.timedelta(seconds=index)
        for index in range(60)
    ]
    app.current_tray.stopwatch_seconds = work_time
    updates = []
    app._update_best_time_records = lambda updated_time: updates.append(updated_time)

    app.complete_tray()

    assert app.completed_tray_times == expected_updates
    assert updates == expected_updates
    assert app.current_tray.master_label_code == ""


def test_complete_tray_reports_state_delete_failure_after_completion(tmp_path):
    app = _completion_app(tmp_path)
    app._delete_current_tray_state = lambda: False
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True

    app.complete_tray()

    assert logged[0]["event"] == "TRAY_COMPLETE"
    assert logged[0]["synchronous"] is True
    assert logged[1]["event"] == "TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION"
    assert logged[1]["detail"]["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.current_tray.master_label_code == ""
    assert app.scanned_listbox.deleted is True
    assert any("임시 상태 파일 삭제에 실패" in message[0][0] for message in app.messages)


def test_build_scan_ok_detail_preserves_scan_contract_keys():
    detail = event_payloads.build_scan_ok_detail(
        "AAA2270730100-001",
        interval_sec=1.234,
        scan_position=3,
        scan_contract_version="v1",
    )

    assert detail == {
        "barcode": "AAA2270730100-001",
        "interval_sec": "1.23",
        "scan_position": 3,
        "barcode_role": "product",
        "raw_barcode": "AAA2270730100-001",
        "parsed_barcode": "AAA2270730100-001",
        "product_barcode": "AAA2270730100-001",
        "scan_contract_version": "v1",
    }


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"barcode": "", "interval_sec": 1.0, "scan_position": 1, "scan_contract_version": "v1"}, "product_barcode"),
        ({"barcode": "BC-1", "interval_sec": -0.1, "scan_position": 1, "scan_contract_version": "v1"}, "interval_sec"),
        ({"barcode": "BC-1", "interval_sec": float("nan"), "scan_position": 1, "scan_contract_version": "v1"}, "interval_sec"),
        ({"barcode": "BC-1", "interval_sec": 1.0, "scan_position": 0, "scan_contract_version": "v1"}, "scan_position"),
        ({"barcode": "BC-1", "interval_sec": 1.0, "scan_position": 1, "scan_contract_version": ""}, "scan_contract_version"),
    ],
)
def test_build_scan_ok_detail_rejects_impossible_payload_values(kwargs, message):
    with pytest.raises(ValueError, match=message):
        event_payloads.build_scan_ok_detail(**kwargs)


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"scanned_barcodes": ["BC-1", "BC-1"]}, "unique"),
        ({"scanned_barcodes": ["BC-1", 2]}, "text values"),
        ({"scanned_barcodes": ["BC-1", "BC-2"], "tray_size": 1}, "scan_count"),
        ({"scanned_barcodes": ["BC-1"], "tray_size": 0}, "tray_capacity"),
        ({"item_code": "BBB2270730100"}, "CLC"),
        ({"tray_size": 3}, "QT"),
        ({"master_label_code": ""}, "master_label_code"),
    ],
)
def test_build_tray_complete_detail_rejects_impossible_payload_values(overrides, message):
    tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=2",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=2,
        stopwatch_seconds=30.0,
    )
    for key, value in overrides.items():
        setattr(tray, key, value)

    with pytest.raises(ValueError, match=message):
        event_payloads.build_tray_complete_detail(
            tray,
            master_label_fields={"CLC": "AAA2270730100", "QT": "2"},
            end_time=datetime.datetime(2026, 6, 22, 9, 2, 0),
        )


@pytest.mark.parametrize(
    ("master_label_fields", "message"),
    [
        ({"CLC": "BBB2270730100", "QT": "2"}, "CLC"),
        ({"CLC": "AAA2270730100", "QT": "bad"}, "QT"),
        ({"CLC": "AAA2270730100", "QT": "0"}, "QT"),
        ("not-a-mapping", "master_label_fields"),
    ],
)
def test_build_tray_complete_detail_rejects_invalid_master_label_fields(master_label_fields, message):
    tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=2",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=2,
        stopwatch_seconds=30.0,
    )

    with pytest.raises(ValueError, match=message):
        event_payloads.build_tray_complete_detail(
            tray,
            master_label_fields=master_label_fields,
            end_time=datetime.datetime(2026, 6, 22, 9, 2, 0),
        )


def test_complete_tray_preserves_active_tray_when_completion_detail_build_fails(tmp_path):
    app = _completion_app(tmp_path)
    app.current_tray.scanned_barcodes = ["BC-1", "BC-1"]
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("completion event should not be logged when detail build fails")
    )

    assert app.complete_tray() is False

    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.current_tray.scanned_barcodes == ["BC-1", "BC-1"]
    assert app.undo_button["state"] == "normal"
    assert app.stopwatch_stopped is False
    assert app.idle_stopped is False
    assert app.state_deleted is False
    assert app.scanned_listbox.deleted is False
    assert app.summaries_updated is False
    assert app.ui_reset is False
    assert app.messages[0][0][0].startswith("트레이 완료 기록 생성에 실패")
    assert not Path(app.log_file_path).exists()


def test_complete_tray_preserves_active_tray_when_completion_log_fails(tmp_path):
    app = _completion_app(tmp_path)
    app.log_file_path = ""

    assert app.complete_tray() is False

    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.current_tray.scanned_barcodes == ["BC-1", "BC-2"]
    assert app.undo_button["state"] == "normal"
    assert app.stopwatch_stopped is False
    assert app.idle_stopped is False
    assert app.state_deleted is False
    assert app.scanned_listbox.deleted is False
    assert app.messages


def test_submit_current_tray_rolls_back_partial_flag_when_completion_log_fails(tmp_path, monkeypatch):
    app = _completion_app(tmp_path)
    app.log_file_path = ""
    app.current_tray.is_partial_submission = False
    app._update_last_activity_time = lambda: setattr(app, "activity_updated", True)
    app._schedule_focus_return = lambda: setattr(app, "focus_scheduled", True)
    monkeypatch.setattr(container_audit_module.messagebox, "askyesno", lambda *args, **kwargs: True)

    app.submit_current_tray()

    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.current_tray.is_partial_submission is False
    assert app.activity_updated is True
    assert app.focus_scheduled is True


def test_park_current_tray_logs_identifying_detail(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1", "BC-2"],
        scan_times=[
            datetime.datetime(2026, 6, 22, 9, 1, 0),
            datetime.datetime(2026, 6, 22, 9, 2, 0),
        ],
        tray_size=60,
    )
    app.COLOR_PRIMARY = "primary"
    app.scanned_listbox = DummyListbox()
    app._delete_current_tray_state = lambda: setattr(app, "state_deleted", True) or True
    app._reset_ui_to_waiting_state = lambda: setattr(app, "ui_reset", True)
    app._update_all_summaries = lambda: setattr(app, "summaries_updated", True)
    app._update_parked_trays_list = lambda: setattr(app, "parked_list_updated", True)
    app.show_status_message = lambda *args, **kwargs: setattr(app, "status_message", args)
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True

    assert app.park_current_tray(confirm=False) is True

    assert logged[0]["event"] == "TRAY_PARKED"
    assert logged[0]["detail"]["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"
    assert logged[0]["detail"]["item_code"] == "AAA2270730100"
    assert logged[0]["detail"]["scan_count"] == 2
    assert logged[0]["detail"]["tray_capacity"] == 60
    assert logged[0]["synchronous"] is True
    assert app.current_tray.master_label_code == ""


def test_park_current_tray_snapshot_includes_live_idle_duration(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        total_idle_seconds=5.0,
    )
    app.is_idle = True
    app.last_activity_time = datetime.datetime.now() - datetime.timedelta(minutes=10)
    app.COLOR_PRIMARY = "primary"
    app.scanned_listbox = DummyListbox()
    app._delete_current_tray_state = lambda: True
    app._reset_ui_to_waiting_state = lambda: None
    app._update_all_summaries = lambda: None
    app._update_parked_trays_list = lambda: None
    app.show_status_message = lambda *args, **kwargs: None
    app._log_event = lambda *args, **kwargs: True

    assert app.park_current_tray(confirm=False) is True

    parked_files = list((tmp_path / "parked").glob("parked_*.json"))
    assert len(parked_files) == 1
    parked_state = json.loads(parked_files[0].read_text(encoding="utf-8"))
    assert 595.0 <= parked_state["total_idle_seconds"] <= 615.0


def test_park_current_tray_does_not_overwrite_existing_qr_parked_file(tmp_path, monkeypatch):
    label = "PHS=1|CLC=AAA2270730100|QT=60"
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.current_tray = TraySession(
        master_label_code=label,
        item_code="AAA2270730100",
        item_name="new active",
        scanned_barcodes=["NEW-BC"],
        tray_size=60,
    )
    app.is_idle = False
    store = parked_tray_store.ParkedTrayStore(app.parked_trays_dir)
    parked_path = store.save_state(
        {
            "worker_name": "홍길동",
            "master_label_code": label,
            "item_code": "AAA2270730100",
            "item_name": "existing parked",
            "scanned_barcodes": ["OLD-BC"],
        },
        worker_name="홍길동",
        master_label=label,
    )
    app.parked_tray_store = store
    app._delete_current_tray_state = lambda: (_ for _ in ()).throw(
        AssertionError("current state should not be deleted when parked file already exists")
    )
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("TRAY_PARKED should not be logged when parked file already exists")
    )
    app._update_parked_trays_list = lambda: (_ for _ in ()).throw(
        AssertionError("parked list should not refresh after failed park")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    assert app.park_current_tray(confirm=False) is False

    parked_state = json.loads(parked_path.read_text(encoding="utf-8"))
    assert parked_state["item_name"] == "existing parked"
    assert parked_state["scanned_barcodes"] == ["OLD-BC"]
    assert app.current_tray.master_label_code == label
    assert app.current_tray.scanned_barcodes == ["NEW-BC"]
    assert errors
    assert "작업 보류 중 오류" in errors[0][1]


def test_park_current_tray_rolls_back_when_current_state_delete_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
    )
    app._delete_current_tray_state = lambda: False
    app.scanned_listbox = DummyListbox()
    app._reset_ui_to_waiting_state = lambda: setattr(app, "ui_reset", True)
    app._update_all_summaries = lambda: setattr(app, "summaries_updated", True)
    app._update_parked_trays_list = lambda: setattr(app, "parked_list_updated", True)
    app.show_status_message = lambda *args, **kwargs: setattr(app, "status_message", args)
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("park event should not be logged when current state delete fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    assert app.park_current_tray(confirm=False) is False

    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert list((tmp_path / "parked").glob("parked_*.json")) == []
    assert app.scanned_listbox.deleted is False
    assert not hasattr(app, "ui_reset")
    assert errors


def test_park_current_tray_preserves_current_when_park_audit_log_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.parked_trays_dir = str(tmp_path / "parked")
    app.current_tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
    )
    assert app._save_current_tray_state() is True
    app.scanned_listbox = DummyListbox()
    app._reset_ui_to_waiting_state = lambda: setattr(app, "ui_reset", True)
    app._update_all_summaries = lambda: setattr(app, "summaries_updated", True)
    app._update_parked_trays_list = lambda: setattr(app, "parked_list_updated", True)
    app.show_status_message = lambda *args, **kwargs: setattr(app, "status_message", args)
    app._log_event = lambda *args, **kwargs: False
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    assert app.park_current_tray(confirm=False) is False

    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert list((tmp_path / "parked").glob("parked_*.json")) == []
    restored_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert restored_state["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.scanned_listbox.deleted is False
    assert not hasattr(app, "ui_reset")
    assert not hasattr(app, "summaries_updated")
    assert errors and "보류 기록" in errors[0][1]


def test_restore_parked_tray_saves_current_state_before_deleting_parked_file(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.current_tray = TraySession()
    app.COLOR_PRIMARY = "primary"
    app.COLOR_SUCCESS = "success"
    app.show_status_message = lambda *args, **kwargs: None
    app.show_validation_screen = lambda: None
    app.show_tray_image_var = DummyToggle()
    app._update_tray_image_display = lambda: None
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False, **kwargs: logged.append(
        {"event": event, "detail": {**(detail or {}), **kwargs}, "synchronous": synchronous}
    ) or True
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert not parked_file.exists()
    assert (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert logged[0]["event"] == "TRAY_RESTORED_FROM_PARK"
    assert logged[0]["detail"]["canonical_event_name"] == "TRAY_RESTORED"
    assert logged[0]["detail"]["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"
    assert logged[0]["detail"]["item_code"] == "AAA2270730100"
    assert logged[0]["detail"]["scan_count"] == 1
    assert logged[0]["detail"]["tray_capacity"] == 60


def test_restore_parked_tray_rolls_back_when_restore_audit_log_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.current_tray = TraySession()
    app.COLOR_PRIMARY = "primary"
    app.COLOR_SUCCESS = "success"
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("restore status should not be shown when restore audit fails")
    )
    app.show_validation_screen = lambda: (_ for _ in ()).throw(
        AssertionError("validation should not be shown when restore audit fails")
    )
    app.show_tray_image_var = DummyToggle()
    app._update_tray_image_display = lambda: (_ for _ in ()).throw(
        AssertionError("image should not update when restore audit fails")
    )
    app.refreshed = False
    app._update_parked_trays_list = lambda: setattr(app, "refreshed", True)
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False, **kwargs: logged.append(
        {"event": event, "detail": {**(detail or {}), **kwargs}, "synchronous": synchronous}
    ) and False
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert parked_file.exists()
    assert not (tmp_path / "current.json").exists()
    restored_parked = json.loads(parked_file.read_text(encoding="utf-8"))
    assert restored_parked["master_label_code"] == "PHS=1|CLC=AAA2270730100|QT=60"
    assert app.current_tray.master_label_code == ""
    assert app.refreshed is True
    assert logged[0]["event"] == "TRAY_RESTORED_FROM_PARK"
    assert logged[0]["detail"]["canonical_event_name"] == "TRAY_RESTORED"
    assert logged[0]["synchronous"] is True
    assert errors[0][0] == "작업 기록 실패"


def test_restore_parked_tray_rolls_back_current_state_when_parked_delete_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.current_tray = TraySession()
    app.COLOR_PRIMARY = "primary"
    app.COLOR_SUCCESS = "success"
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("restore status should not be shown when parked delete fails")
    )
    app.show_validation_screen = lambda: (_ for _ in ()).throw(
        AssertionError("validation should not be shown when parked delete fails")
    )
    app.show_tray_image_var = DummyToggle()
    app._update_tray_image_display = lambda: (_ for _ in ()).throw(
        AssertionError("image should not update when parked delete fails")
    )
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("restore event should not be logged when parked delete fails")
    )
    monkeypatch.setattr(
        parked_tray_store.ParkedTrayStore,
        "delete",
        staticmethod(lambda path: (_ for _ in ()).throw(PermissionError("locked"))),
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert parked_file.exists()
    assert not (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == ""
    assert errors
    assert "보류 작업 파일 삭제에 실패" in errors[0][1]


def test_update_parked_trays_list_quarantines_corrupt_parked_file(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.parked_tree = CapturingTree()
    app.COLOR_DANGER = "danger"
    messages = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)
    corrupt_file = tmp_path / "parked_qr_홍길동_corrupt.json"
    corrupt_file.write_text("{not-json}", encoding="utf-8")

    app._update_parked_trays_list()

    assert not corrupt_file.exists()
    assert list(tmp_path.glob("parked_qr_홍길동_corrupt.json.bad-*"))
    assert app.parked_tree.rows == {}
    assert messages
    assert "손상된 보류 작업 파일을 격리했습니다" in messages[0][0]


def test_update_parked_trays_list_quarantines_invalid_utf8_file_and_keeps_valid_rows(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.parked_tree = CapturingTree()
    app.COLOR_DANGER = "danger"
    messages = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)
    corrupt_file = tmp_path / "parked_qr_홍길동_invalid_utf8.json"
    corrupt_file.write_bytes(b"\xff\xfe\xfa")
    valid_file = tmp_path / "parked_qr_홍길동_valid.json"
    storage_utils.atomic_write_json(
        valid_file,
        _valid_tray_state_payload(
            item_name="valid parked",
            scanned_barcodes=["BC-1", "BC-2"],
            scan_times=[
                datetime.datetime(2026, 6, 22, 9, 1, 0).isoformat(),
                datetime.datetime(2026, 6, 22, 9, 2, 0).isoformat(),
            ],
        ),
        ensure_ascii=False,
    )

    app._update_parked_trays_list()

    assert not corrupt_file.exists()
    assert list(tmp_path.glob("parked_qr_홍길동_invalid_utf8.json.bad-*"))
    assert app.parked_tree.rows == {str(valid_file): ("valid parked", "2 개")}
    assert messages


def test_update_parked_trays_list_quarantines_semantically_invalid_parked_file(tmp_path):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.TRAY_SIZE = 60
    app.parked_tree = CapturingTree()
    app.COLOR_DANGER = "danger"
    messages = []
    app.show_status_message = lambda *args, **kwargs: messages.append(args)
    parked_file = tmp_path / "parked_qr_홍길동_invalid.json"
    storage_utils.atomic_write_json(
        parked_file,
        _valid_tray_state_payload(item_code=""),
        ensure_ascii=False,
    )

    app._update_parked_trays_list()

    assert not parked_file.exists()
    assert list(tmp_path.glob("parked_qr_홍길동_invalid.json.bad-*"))
    assert app.parked_tree.rows == {}
    assert messages


def test_restore_parked_tray_rejects_other_worker_payload_without_deleting_file(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="ACTIVE-ITEM")
    app.refreshed = False
    app._update_parked_trays_list = lambda: setattr(app, "refreshed", True)
    app._restore_tray_from_state = lambda state: (_ for _ in ()).throw(
        AssertionError("other worker parked tray should not be restored")
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesnocancel",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("restore prompt should not open")),
    )
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))
    parked_file = tmp_path / "parked_qr_다른작업자_fixture.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="다른작업자"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert parked_file.exists()
    assert not (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == "ACTIVE"
    assert app.refreshed is True
    assert warnings


def test_restore_parked_tray_deletes_completed_label_without_restoring(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.current_tray = TraySession()
    label = "PHS=1|CLC=AAA2270730100|QT=60"
    app.completed_master_labels = {label_qr.canonical_master_label_key(label)}
    app.refreshed = False
    app._update_parked_trays_list = lambda: setattr(app, "refreshed", True)
    app._restore_tray_from_state = lambda state: (_ for _ in ()).throw(
        AssertionError("completed parked tray should not be restored")
    )
    app._save_tray_state_snapshot = lambda state: (_ for _ in ()).throw(
        AssertionError("completed parked tray should not be written as current state")
    )
    app.show_validation_screen = lambda: (_ for _ in ()).throw(
        AssertionError("completed parked tray should not show validation")
    )
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("completed parked tray should not emit restore event")
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "askyesnocancel",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("overwrite prompt should not open")),
    )
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    parked_session = TraySession(
        master_label_code=label,
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert not parked_file.exists()
    assert not (tmp_path / "current.json").exists()
    assert app.current_tray.master_label_code == ""
    assert app.refreshed is True
    assert warnings[0][0] == "복원 실패"
    assert "이미 완료된 보류 작업" in warnings[0][1]


def test_restore_parked_tray_does_not_overwrite_active_work_if_parking_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.TRAY_SIZE = 60
    app.current_tray = TraySession(master_label_code="ACTIVE", item_code="ACTIVE")
    app.park_current_tray = lambda: False
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *args, **kwargs: True)
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert app.current_tray.master_label_code == "ACTIVE"
    assert parked_file.exists()


def test_restore_parked_tray_does_not_overwrite_active_work_when_discard_log_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.current_tray = TraySession(
        master_label_code="ACTIVE",
        item_code="ACTIVE-ITEM",
        item_name="active item",
        scanned_barcodes=["ACTIVE-BC"],
    )
    assert app._save_current_tray_state() is True
    app._log_event = lambda *args, **kwargs: False
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("restore status should not be shown when discard audit fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *args, **kwargs: False)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert app.current_tray.master_label_code == "ACTIVE"
    assert app.current_tray.scanned_barcodes == ["ACTIVE-BC"]
    restored_state = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert restored_state["master_label_code"] == "ACTIVE"
    assert restored_state["scanned_barcodes"] == ["ACTIVE-BC"]
    assert parked_file.exists()
    assert errors
    assert errors[0][0] == "작업 기록 실패"


def test_restore_parked_tray_keeps_active_work_when_restored_state_save_fails(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.TRAY_SIZE = 60
    app.current_tray = TraySession(
        master_label_code="ACTIVE",
        item_code="ACTIVE-ITEM",
        item_name="active item",
        scanned_barcodes=["ACTIVE-BC"],
    )
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    app._save_tray_state_snapshot = lambda state: False
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("restore status should not be shown when restored state save fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *args, **kwargs: False)
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert logged == []
    assert app.current_tray.master_label_code == "ACTIVE"
    assert app.current_tray.scanned_barcodes == ["ACTIVE-BC"]
    assert parked_file.exists()
    assert errors


def test_restore_parked_tray_logs_current_work_discard_when_overwritten(tmp_path, monkeypatch):
    app = _headless_app()
    app.worker_name = "홍길동"
    app.parked_trays_dir = str(tmp_path)
    app.save_folder = str(tmp_path)
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.TRAY_SIZE = 60
    app.COLOR_PRIMARY = "primary"
    app.COLOR_SUCCESS = "success"
    app.current_tray = TraySession(
        master_label_code="ACTIVE",
        item_code="ACTIVE-ITEM",
        item_name="active item",
        scanned_barcodes=["ACTIVE-BC"],
    )
    app.show_status_message = lambda *args, **kwargs: None
    app.show_validation_screen = lambda: None
    app.show_tray_image_var = DummyToggle()
    app._update_tray_image_display = lambda: None
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False, **kwargs: logged.append(
        {"event": event, "detail": {**(detail or {}), **kwargs}, "synchronous": synchronous}
    ) or True
    monkeypatch.setattr(container_audit_module.messagebox, "askyesnocancel", lambda *args, **kwargs: False)
    parked_file = tmp_path / "parked_qr_홍길동_fixture.json"
    parked_session = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=60",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["BC-1"],
        scan_times=[datetime.datetime(2026, 6, 22, 9, 1, 0)],
        tray_size=60,
        mismatch_error_count=0,
        total_idle_seconds=0.0,
        stopwatch_seconds=30.0,
        start_time=datetime.datetime(2026, 6, 22, 9, 0, 0),
    )
    storage_utils.atomic_write_json(
        parked_file,
        tray_state.tray_session_to_state(parked_session, worker_name="홍길동"),
        ensure_ascii=False,
    )

    app.restore_parked_tray(str(parked_file))

    assert logged[0]["event"] == "TRAY_DISCARDED_BY_OPERATOR"
    assert logged[0]["synchronous"] is True
    assert logged[0]["detail"]["reason"] == "restore_parked_overwrite_current"
    assert logged[0]["detail"]["master_label_code"] == "ACTIVE"
    assert logged[0]["detail"]["scan_count"] == 1
    assert app.current_tray.master_label_code == "PHS=1|CLC=AAA2270730100|QT=60"
    assert not parked_file.exists()


@pytest.mark.parametrize(
    ("latest", "current", "expected"),
    [
        ("v2.0.10", "v2.0.9", True),
        ("v2.0.9", "v2.0.10", False),
        ("2.1.0", "v2.0.10", True),
        ("v2.0.9", "v2.0.9", False),
        ("v2.0.10-hotfix", "v2.0.9", False),
        ("v2.0.10", "current", False),
    ],
)
def test_version_comparison_uses_semantic_version_order(latest, current, expected):
    assert container_audit_module._is_newer_version(latest, current) is expected


def test_replacement_removed_item_uses_current_product_barcodes_key():
    app = _headless_app()
    app.replacement_context = {
        "original_details": {"product_barcodes": ["BC-1"]},
        "removed_items": [],
        "items_to_remove_count": 1,
    }
    app.success_sound = None
    app.finalized = False
    app._finalize_replacement = lambda: setattr(app, "finalized", True)
    app._update_current_item_label = lambda: None
    app.show_fullscreen_warning = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("valid product barcode should not warn")
    )

    app._handle_removed_item_scan("BC-1")

    assert app.replacement_context["removed_items"] == ["BC-1"]
    assert app.finalized is True


def test_replacement_additional_item_rejects_duplicate_from_current_product_key():
    app = _headless_app()
    app.replacement_context = {
        "original_details": {"scanned_product_barcodes": ["BC-1"]},
        "additional_items": [],
        "items_needed": 1,
    }
    app.warnings = []
    app.COLOR_DANGER = "danger"
    app.show_fullscreen_warning = lambda *args, **kwargs: app.warnings.append(args)

    app._handle_additional_item_scan("BC-1")

    assert app.replacement_context["additional_items"] == []
    assert app.warnings


def test_replacement_rejects_new_master_label_with_different_item_code(monkeypatch):
    app = _headless_app()
    app.replacement_context = {
        "new_data": {"CLC": "BBB2270730100", "QT": "1"},
        "original_details": {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=1",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
        },
    }
    app.cancel_master_label_replacement = lambda: setattr(app, "cancelled", True)
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._compare_quantities_and_proceed()

    assert app.cancelled is True
    assert warnings


def test_replacement_rejects_original_master_label_item_code_mismatch(monkeypatch):
    app = _headless_app()
    app.replacement_context = {
        "new_data": {"CLC": "AAA2270730100", "QT": "1"},
        "original_details": {
            "master_label_code": "PHS=1|CLC=BBB2270730100|QT=1",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
        },
    }
    app.cancel_master_label_replacement = lambda: setattr(app, "cancelled", True)
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._compare_quantities_and_proceed()

    assert app.cancelled is True
    assert warnings[0][0] == "품목 불일치"
    assert "기존 현품표" in warnings[0][1]


def test_replacement_partial_completion_uses_product_barcode_quantity():
    app = _headless_app()
    app.replacement_context = {
        "new_data": {"CLC": "AAA2270730100", "QT": "2"},
        "original_details": {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
            "scan_count": 2,
            "tray_capacity": 60,
            "is_partial_submission": True,
            "quantity_basis": "PRODUCT_BARCODE",
        },
    }
    app._finalize_replacement = lambda: setattr(app, "finalized", True)
    app._update_current_item_label = lambda: setattr(app, "awaiting_scan", True)

    app._compare_quantities_and_proceed()

    assert app.replacement_context["old_qty"] == 2
    assert app.replacement_context["new_qty"] == 2
    assert app.finalized is True
    assert not hasattr(app, "awaiting_scan")


def test_replacement_unknown_old_quantity_cancels_without_fabricating_delta(monkeypatch):
    app = _headless_app()
    app.replacement_context = {
        "new_data": {"CLC": "AAA2270730100", "QT": "60"},
        "original_details": {
            "master_label_code": "OLD-LABEL-WITHOUT-QTY",
            "item_code": "AAA2270730100",
            "product_barcodes": [],
        },
    }
    warnings = []
    app.cancelled = False
    app.cancel_master_label_replacement = lambda: setattr(app, "cancelled", True)
    app._finalize_replacement = lambda: (_ for _ in ()).throw(AssertionError("unknown old quantity should not finalize"))
    app._update_current_item_label = lambda: (_ for _ in ()).throw(AssertionError("unknown old quantity should not await scans"))
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._compare_quantities_and_proceed()

    assert warnings
    assert app.cancelled is True
    assert "old_qty" not in app.replacement_context


def test_replacement_rejects_equivalent_new_master_label_identity():
    app = _headless_app()
    app.master_label_replace_state = "awaiting_new_replacement"
    app.replacement_context = {"old_label": '{"CLC":"AAA2270730100","QT":"60"}'}
    app.COLOR_DANGER = "danger"
    app.warnings = []
    app.show_fullscreen_warning = lambda *args, **kwargs: app.warnings.append(args)
    app._perform_historical_master_label_swap = lambda: setattr(app, "swapped", True)

    app._handle_historical_replacement_scan("QT=60|CLC=AAA2270730100")

    assert app.warnings
    assert "new_label" not in app.replacement_context
    assert not hasattr(app, "swapped")


def test_replacement_rejects_already_completed_new_master_label():
    app = _headless_app()
    app.master_label_replace_state = "awaiting_new_replacement"
    app.replacement_context = {"old_label": "PHS=1|CLC=AAA2270730100|QT=1|LOT=OLD"}
    completed_new = "PHS=1|CLC=AAA2270730100|QT=1|LOT=NEW"
    app.completed_master_labels = {label_qr.canonical_master_label_key(completed_new)}
    app.COLOR_DANGER = "danger"
    app.warnings = []
    app.show_fullscreen_warning = lambda *args, **kwargs: app.warnings.append(args)
    app._perform_historical_master_label_swap = lambda: setattr(app, "swapped", True)

    app._handle_historical_replacement_scan(completed_new)

    assert app.warnings[0][0] == "현품표 중복"
    assert "new_label" not in app.replacement_context
    assert not hasattr(app, "swapped")


def test_replacement_additional_item_rejects_different_item_code():
    app = _headless_app()
    app.COLOR_DANGER = "danger"
    app.replacement_context = {
        "expected_item_code": "AAA2270730100",
        "original_details": {"product_barcodes": ["AAA2270730100-001"]},
        "additional_items": [],
        "items_needed": 1,
    }
    app.warnings = []
    app.show_fullscreen_warning = lambda *args, **kwargs: app.warnings.append(args)

    app._handle_additional_item_scan("BBB2270730100-EXTRA")

    assert app.replacement_context["additional_items"] == []
    assert app.warnings


def test_replacement_additional_item_rejects_catalog_resolved_overlapping_item_code():
    app = _headless_app()
    app.COLOR_DANGER = "danger"
    app.ITEM_CODE_LENGTH = 9
    app.items_data = [
        {"Item Code": "AAA227073", "Item Name": "short item"},
        {"Item Code": "AAA2270730100", "Item Name": "long item"},
    ]
    app.item_catalog = item_catalog.ItemCatalog(app.items_data)
    app.replacement_context = {
        "expected_item_code": "AAA227073",
        "original_details": {"product_barcodes": []},
        "additional_items": [],
        "items_needed": 1,
    }
    app.warnings = []
    app.show_fullscreen_warning = lambda *args, **kwargs: app.warnings.append(args)

    app._handle_additional_item_scan("PREFIX-AAA2270730100-EXTRA")

    assert app.replacement_context["additional_items"] == []
    assert app.warnings[0][0] == "품목 코드 불일치"


def test_replacement_additional_item_rejects_ambiguous_catalog_item_codes():
    app = _headless_app()
    app.COLOR_DANGER = "danger"
    app.ITEM_CODE_LENGTH = 13
    app.items_data = [
        {"Item Code": "AAA2270730100", "Item Name": "fixture item"},
        {"Item Code": "BBB2270730100", "Item Name": "other item"},
    ]
    app.item_catalog = item_catalog.ItemCatalog(app.items_data)
    app.replacement_context = {
        "expected_item_code": "AAA2270730100",
        "original_details": {"product_barcodes": []},
        "additional_items": [],
        "items_needed": 1,
    }
    app.warnings = []
    app.show_fullscreen_warning = lambda *args, **kwargs: app.warnings.append(args)

    app._handle_additional_item_scan("AAA2270730100-BBB2270730100-EXTRA")

    assert app.replacement_context["additional_items"] == []
    assert app.warnings[0][0] == "품목 코드 모호"


def test_replacement_additional_item_rejects_item_code_without_product_suffix():
    app = _headless_app()
    app.COLOR_DANGER = "danger"
    app.ITEM_CODE_LENGTH = 13
    app.replacement_context = {
        "expected_item_code": "AAA2270730100",
        "original_details": {"product_barcodes": ["AAA2270730100-001"]},
        "additional_items": [],
        "items_needed": 1,
    }
    app.warnings = []
    app.show_fullscreen_warning = lambda *args, **kwargs: app.warnings.append(args)

    app._handle_additional_item_scan("AAA2270730100")

    assert app.replacement_context["additional_items"] == []
    assert app.warnings
    assert app.warnings[0][0] == "바코드 형식 오류"


def test_finalize_replacement_logs_applied_synchronously_without_cancel_event(monkeypatch):
    app = _headless_app()
    app.worker_name = "검사자"
    app.SOURCE_SYSTEM = "container_audit"
    app.SOURCE_TRANSPORT_OR_DATASET = "legacy_transfer_csv"
    app.completed_master_labels = set()
    app.master_label_replace_state = "awaiting_new_replacement"
    app.replacement_context = {
        "found_log_file": "이적작업이벤트로그_검사자_20260623.csv",
        "found_source_file_id": "검사작업이벤트로그_검사자_20260622.csv",
        "found_row_index": 2,
        "found_source_byte_offset": 123,
        "found_row_hash": "old-row-hash",
        "original_details": {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=1",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
            "scan_count": 1,
            "tray_capacity": 1,
            "barcode_count": 1,
        },
        "old_label": "PHS=1|CLC=AAA2270730100|QT=1",
        "new_label": "PHS=1|CLC=AAA2270730100|QT=1|LOT=NEW",
        "old_qty": 1,
        "new_qty": 1,
    }
    app._stable_hash = event_contracts.stable_hash
    app.updated = False
    app.item_label_updated = False
    app._update_all_summaries = lambda: setattr(app, "updated", True)
    app._update_current_item_label = lambda: setattr(app, "item_label_updated", True)
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    infos = []
    monkeypatch.setattr(container_audit_module.messagebox, "showinfo", lambda *args, **kwargs: infos.append(args))

    app._finalize_replacement()

    assert [entry["event"] for entry in logged] == ["MASTER_LABEL_REPLACEMENT_APPLIED"]
    assert logged[0]["synchronous"] is True
    assert logged[0]["detail"]["original_event_identity"]["source_file_id"] == "검사작업이벤트로그_검사자_20260622.csv"
    assert app.master_label_replace_state is None
    assert app.replacement_context == {}
    assert app.updated is True
    assert app.item_label_updated is True
    assert app._is_completed_master_label("PHS=1|CLC=AAA2270730100|QT=1") is True
    assert app._is_completed_master_label("PHS=1|CLC=AAA2270730100|QT=1|LOT=NEW") is True
    assert infos


def test_cancel_master_label_replacement_logs_synchronously_before_clearing_state(monkeypatch):
    app = _headless_app()
    app.master_label_replace_state = "awaiting_additional_items"
    app.replacement_context = {
        "old_label": "OLD",
        "new_label": "NEW",
        "additional_items": ["BC-1"],
    }
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {
            "event": event,
            "detail": detail,
            "synchronous": synchronous,
            "state_during_log": app.master_label_replace_state,
            "context_during_log": dict(app.replacement_context),
        }
    ) or True
    app.show_status_message = lambda *args, **kwargs: setattr(app, "status_shown", True)
    app._update_current_item_label = lambda: setattr(app, "item_label_updated", True)

    assert app.cancel_master_label_replacement() is True

    assert logged[0]["event"] == "HISTORICAL_REPLACE_CANCEL"
    assert logged[0]["synchronous"] is True
    assert logged[0]["detail"]["reason"] == "operator_cancel"
    assert logged[0]["state_during_log"] == "awaiting_additional_items"
    assert logged[0]["context_during_log"]["old_label"] == "OLD"
    assert app.master_label_replace_state is None
    assert app.replacement_context == {}
    assert app.status_shown is True
    assert app.item_label_updated is True


def test_cancel_master_label_replacement_preserves_state_when_cancel_log_fails(monkeypatch):
    app = _headless_app()
    app.master_label_replace_state = "awaiting_removed_items"
    app.replacement_context = {"old_label": "OLD", "removed_items": ["BC-1"]}
    app._log_event = lambda *args, **kwargs: False
    app.show_status_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("cancel status should not show when cancel audit fails")
    )
    app._update_current_item_label = lambda: (_ for _ in ()).throw(
        AssertionError("item label should not update when cancel audit fails")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    assert app.cancel_master_label_replacement() is False

    assert app.master_label_replace_state == "awaiting_removed_items"
    assert app.replacement_context == {"old_label": "OLD", "removed_items": ["BC-1"]}
    assert errors[0][0] == "교체 취소 기록 실패"


def test_finalize_replacement_keeps_state_when_applied_log_fails(monkeypatch):
    app = _headless_app()
    app.worker_name = "검사자"
    app.SOURCE_SYSTEM = "container_audit"
    app.SOURCE_TRANSPORT_OR_DATASET = "legacy_transfer_csv"
    app.completed_master_labels = set()
    app.master_label_replace_state = "awaiting_new_replacement"
    context = {
        "found_log_file": "이적작업이벤트로그_검사자_20260623.csv",
        "found_row_index": 2,
        "original_details": {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=1",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
        },
        "old_label": "PHS=1|CLC=AAA2270730100|QT=1",
        "new_label": "PHS=1|CLC=AAA2270730100|QT=1|LOT=NEW",
        "old_qty": 1,
        "new_qty": 1,
    }
    app.replacement_context = dict(context)
    app._stable_hash = event_contracts.stable_hash
    app._log_event = lambda *args, **kwargs: False
    app._update_all_summaries = lambda: setattr(app, "updated", True)
    app._update_current_item_label = lambda: setattr(app, "item_label_updated", True)
    infos = []
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showinfo", lambda *args, **kwargs: infos.append(args))
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app._finalize_replacement()

    assert app.master_label_replace_state == "awaiting_new_replacement"
    assert app.replacement_context == context
    assert app.completed_master_labels == set()
    assert not hasattr(app, "updated")
    assert not hasattr(app, "item_label_updated")
    assert infos == []
    assert errors


def test_exchange_session_honors_quantity_and_item_catalog_spec(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession()
    app.exchange_quantity_var = DummyIntVar(2)
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app.success_sound = None
    app.exchange_complete_button = DummyButton()
    app.exchange_quantity_spin = DummyButton()
    app._update_exchange_display = lambda: None
    app._update_exchange_status = lambda: None
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showerror",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("valid exchange scan should not error")),
    )

    app._process_exchange_scan("PREFIX-AAA2270730100-DEFECT-1")
    app._process_exchange_scan("PREFIX-AAA2270730100-DEFECT-2")
    app._process_exchange_scan("PREFIX-AAA2270730100-GOOD-1")
    app._process_exchange_scan("PREFIX-AAA2270730100-GOOD-2")

    session = app.current_exchange_session
    assert session.target_quantity == 2
    assert session.item_code == "AAA2270730100"
    assert session.item_spec == "fixture spec"
    assert session.defective_barcodes == ["PREFIX-AAA2270730100-DEFECT-1", "PREFIX-AAA2270730100-DEFECT-2"]
    assert session.good_barcodes == ["PREFIX-AAA2270730100-GOOD-1", "PREFIX-AAA2270730100-GOOD-2"]
    assert app.exchange_quantity_spin.config_calls == [{"state": container_audit_module.tk.DISABLED}]
    assert app.exchange_complete_button.config_calls[-1]["state"] == container_audit_module.tk.NORMAL


def test_show_exchange_dialog_focuses_existing_dialog_without_resetting_partial_session(monkeypatch):
    app = _headless_app()
    app.current_tray = TraySession()
    session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=2,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD-1"],
    )
    app.current_exchange_session = session

    class ExistingDialog:
        def __init__(self):
            self.calls = []

        def winfo_exists(self):
            return True

        def lift(self):
            self.calls.append("lift")

        def focus_force(self):
            self.calls.append("focus_force")

    dialog = ExistingDialog()
    app.exchange_dialog = dialog
    monkeypatch.setattr(
        container_audit_module.tk,
        "Toplevel",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("existing exchange dialog should be reused")),
    )
    monkeypatch.setattr(
        container_audit_module.messagebox,
        "showwarning",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("existing exchange dialog should not warn")),
    )

    app.show_exchange_dialog()

    assert app.current_exchange_session is session
    assert app.current_exchange_session.defective_barcodes == ["AAA2270730100-BAD-1"]
    assert app.exchange_dialog is dialog
    assert dialog.calls == ["lift", "focus_force"]


@pytest.mark.parametrize("quantity_var", [DummyIntVar(0), DummyIntVar(11), DummyIntVar("abc"), DummyIntVar(True), RaisingIntVar()])
def test_exchange_scan_rejects_invalid_quantity_without_starting_session(monkeypatch, quantity_var):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession()
    app.exchange_quantity_var = quantity_var
    app.exchange_quantity_spin = DummyButton()
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app._update_exchange_display = lambda: (_ for _ in ()).throw(
        AssertionError("display should not update when quantity is invalid")
    )
    app._update_exchange_status = lambda: (_ for _ in ()).throw(
        AssertionError("status should not update when quantity is invalid")
    )
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._process_exchange_scan("PREFIX-AAA2270730100-DEFECT-1")

    assert app.current_exchange_session.current_step == "not_started"
    assert app.current_exchange_session.target_quantity == 1
    assert app.current_exchange_session.defective_barcodes == []
    assert app.exchange_quantity_spin.config_calls == []
    assert warnings
    assert warnings[0][0] == "수량 미설정"


def test_exchange_scan_rejects_invalid_in_progress_state_without_updating_display(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession(current_step="scan_defective", target_quantity=True)
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app._update_exchange_display = lambda: (_ for _ in ()).throw(
        AssertionError("display should not update when in-progress exchange state is invalid")
    )
    app._update_exchange_status = lambda: (_ for _ in ()).throw(
        AssertionError("status should not update when in-progress exchange state is invalid")
    )
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app._process_exchange_scan("PREFIX-AAA2270730100-DEFECT-1")

    assert app.current_exchange_session.item_code == ""
    assert app.current_exchange_session.defective_barcodes == []
    assert errors
    assert errors[0][0] == "교환 오류"


def test_exchange_scan_rejects_item_code_without_product_suffix(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession()
    app.exchange_quantity_var = DummyIntVar(1)
    app.items_data = [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    app._update_exchange_display = lambda: None
    app._update_exchange_status = lambda: None
    app.errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: app.errors.append(args))

    app._process_exchange_scan("AAA2270730100")

    assert app.current_exchange_session.item_code == ""
    assert app.errors


def test_cancel_exchange_logs_partial_scans_before_resetting_session(monkeypatch):
    app = _headless_app()
    session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        target_quantity=2,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD-1", "AAA2270730100-BAD-2"],
        good_barcodes=["AAA2270730100-GOOD-1"],
    )
    app.current_exchange_session = session
    app.destroyed = False
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    app.exchange_quantity_spin = DummyButton()
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {
            "event": event,
            "detail": detail,
            "synchronous": synchronous,
            "session_during_log": app.current_exchange_session,
        }
    ) or True

    assert app._cancel_exchange() is True

    assert logged[0]["event"] == "PRODUCT_EXCHANGE_CANCELLED"
    assert logged[0]["synchronous"] is True
    assert logged[0]["session_during_log"] is session
    assert logged[0]["detail"]["exchange_id"] == session.exchange_id
    assert logged[0]["detail"]["defective_count"] == 2
    assert logged[0]["detail"]["good_count"] == 1
    assert logged[0]["detail"]["reason"] == "operator_cancel"
    assert app.current_exchange_session is not session
    assert app.current_exchange_session.current_step == "not_started"
    assert app.destroyed is True
    assert app.exchange_dialog is None
    assert app.exchange_quantity_spin is None


def test_cancel_exchange_preserves_partial_session_when_cancel_log_fails(monkeypatch):
    app = _headless_app()
    session = ProductExchangeSession(
        item_code="AAA2270730100",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD-1"],
    )
    app.current_exchange_session = session
    app.destroyed = False
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    app._log_event = lambda *args, **kwargs: False
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    assert app._cancel_exchange() is False

    assert app.current_exchange_session is session
    assert app.destroyed is False
    assert errors[0][0] == "교환 취소 기록 실패"


def test_cancel_exchange_without_scans_closes_without_logging():
    app = _headless_app()
    session = ProductExchangeSession(current_step="not_started")
    app.current_exchange_session = session
    app.destroyed = False
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    app.exchange_quantity_spin = DummyButton()
    app._log_event = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("empty exchange cancel should not emit an audit event")
    )

    assert app._cancel_exchange() is True

    assert app.current_exchange_session is not session
    assert app.destroyed is True
    assert app.exchange_dialog is None
    assert app.exchange_quantity_spin is None


def test_product_exchange_scan_helper_updates_session_and_builds_detail():
    catalog = item_catalog.ItemCatalog(
        [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    )
    session = product_exchange.ProductExchangeSession(target_quantity=1, current_step="scan_defective")

    defective = product_exchange.apply_exchange_scan(
        session,
        "PREFIX-AAA2270730100-DEFECT",
        item_catalog=catalog,
        item_code_length=13,
    )
    good = product_exchange.apply_exchange_scan(
        session,
        "PREFIX-AAA2270730100-GOOD",
        item_catalog=catalog,
        item_code_length=13,
    )
    detail = product_exchange.build_exchange_completion_detail(session)

    assert defective.status == "accepted"
    assert session.current_step == "scan_good"
    assert good.complete_ready is True
    assert detail["exchange_pairs"] == [
        {"defective": "PREFIX-AAA2270730100-DEFECT", "good": "PREFIX-AAA2270730100-GOOD"}
    ]
    assert detail["item_code"] == "AAA2270730100"
    assert detail["item_spec"] == "fixture spec"
    assert detail["defective_barcodes"] == ["PREFIX-AAA2270730100-DEFECT"]
    assert detail["good_barcodes"] == ["PREFIX-AAA2270730100-GOOD"]
    assert detail["exchange_contract_version"] == product_exchange.EXCHANGE_CONTRACT_VERSION
    assert detail["exchange_id"] == session.exchange_id
    assert detail["pair_count"] == 1
    assert detail["exchange_count"] == 1


def test_product_exchange_rejects_ambiguous_catalog_item_codes():
    session = product_exchange.ProductExchangeSession(target_quantity=1, current_step="scan_defective")
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": "AAA2270730100", "Item Name": "fixture item"},
            {"Item Code": "BBB2270730100", "Item Name": "other item"},
        ]
    )

    result = product_exchange.apply_exchange_scan(
        session,
        "AAA2270730100-BBB2270730100-BAD",
        item_catalog=catalog,
        item_code_length=13,
    )

    assert result.status == "error"
    assert result.title == "품목 코드 모호"
    assert session.item_code == ""


def test_product_exchange_rejects_catalog_resolved_different_overlapping_item_code():
    session = product_exchange.ProductExchangeSession(
        target_quantity=1,
        current_step="scan_defective",
        item_code="AAA227073",
        item_name="short item",
    )
    catalog = item_catalog.ItemCatalog(
        [
            {"Item Code": "AAA227073", "Item Name": "short item"},
            {"Item Code": "AAA2270730100", "Item Name": "long item"},
        ]
    )

    result = product_exchange.apply_exchange_scan(
        session,
        "PREFIX-AAA2270730100-BAD",
        item_catalog=catalog,
        item_code_length=9,
    )

    assert result.status == "error"
    assert result.title == "품목 코드 불일치"
    assert session.defective_barcodes == []


def test_product_exchange_completion_detail_has_stable_session_identity_and_hash():
    first = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    second = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )

    first_detail = product_exchange.build_exchange_completion_detail(first)
    repeated_detail = product_exchange.build_exchange_completion_detail(first)
    second_detail = product_exchange.build_exchange_completion_detail(second)

    assert repeated_detail["exchange_id"] == first_detail["exchange_id"]
    assert repeated_detail["evidence_hash"] == first_detail["evidence_hash"]
    assert second_detail["exchange_id"] != first_detail["exchange_id"]
    assert second_detail["evidence_hash"] != first_detail["evidence_hash"]


def test_product_exchange_completion_evidence_hash_uses_stable_hash_unicode_normalization():
    composed = product_exchange.ProductExchangeSession(
        exchange_id="exchange-fixed",
        item_code="AAA2270730100",
        item_name="\uac00",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    decomposed = product_exchange.ProductExchangeSession(
        exchange_id="exchange-fixed",
        item_code="AAA2270730100",
        item_name="\u1100\u1161",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )

    composed_detail = product_exchange.build_exchange_completion_detail(composed)
    decomposed_detail = product_exchange.build_exchange_completion_detail(decomposed)

    assert composed_detail["item_name"] != decomposed_detail["item_name"]
    assert composed_detail["evidence_hash"] == decomposed_detail["evidence_hash"]
    expected = dict(composed_detail)
    expected.pop("evidence_hash")
    assert composed_detail["evidence_hash"] == event_contracts.stable_hash(expected)


def test_product_exchange_rejects_scans_beyond_target_quantity():
    catalog = item_catalog.ItemCatalog(
        [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    )
    session = product_exchange.ProductExchangeSession(target_quantity=1, current_step="scan_defective")
    first = product_exchange.apply_exchange_scan(
        session,
        "PREFIX-AAA2270730100-DEFECT",
        item_catalog=catalog,
        item_code_length=13,
    )
    good = product_exchange.apply_exchange_scan(
        session,
        "PREFIX-AAA2270730100-GOOD",
        item_catalog=catalog,
        item_code_length=13,
    )
    extra = product_exchange.apply_exchange_scan(
        session,
        "PREFIX-AAA2270730100-EXTRA",
        item_catalog=catalog,
        item_code_length=13,
    )

    assert first.status == "accepted"
    assert good.complete_ready is True
    assert extra.status == "warning"
    assert extra.title == "수량 초과"
    assert session.good_barcodes == ["PREFIX-AAA2270730100-GOOD"]


@pytest.mark.parametrize(
    ("session_kwargs", "barcode", "item_code_length", "expected_message"),
    [
        ({"target_quantity": True}, "PREFIX-AAA2270730100-DEFECT", 13, "목표 수량"),
        ({"target_quantity": "1"}, "PREFIX-AAA2270730100-DEFECT", 13, "목표 수량"),
        ({"target_quantity": 11}, "PREFIX-AAA2270730100-DEFECT", 13, "목표 수량"),
        ({"target_quantity": 1}, "PREFIX-AAA2270730100-DEFECT", 0, "길이 설정"),
        ({"target_quantity": 1}, "PREFIX-AAA2270730100-DEFECT", True, "길이 설정"),
        ({"target_quantity": 1}, None, 13, "올바르지 않습니다"),
        ({"target_quantity": 1}, "   ", 13, "올바르지 않습니다"),
        ({"target_quantity": 1, "defective_barcodes": ["DUP", "DUP"]}, "PREFIX-AAA2270730100-DEFECT", 13, "목록"),
        ({"target_quantity": 1, "good_barcodes": [2]}, "PREFIX-AAA2270730100-DEFECT", 13, "목록"),
    ],
)
def test_product_exchange_scan_helper_rejects_invalid_state_without_mutation(
    session_kwargs,
    barcode,
    item_code_length,
    expected_message,
):
    catalog = item_catalog.ItemCatalog(
        [{"Item Code": "AAA2270730100", "Item Name": "fixture item", "Spec": "fixture spec"}]
    )
    session = product_exchange.ProductExchangeSession(current_step="scan_defective", **session_kwargs)
    before = {
        "item_code": session.item_code,
        "item_name": session.item_name,
        "defective_barcodes": list(session.defective_barcodes),
        "good_barcodes": list(session.good_barcodes),
        "current_step": session.current_step,
    }

    result = product_exchange.apply_exchange_scan(
        session,
        barcode,
        item_catalog=catalog,
        item_code_length=item_code_length,
    )

    assert result.status == "error"
    assert expected_message in result.message
    assert session.item_code == before["item_code"]
    assert session.item_name == before["item_name"]
    assert session.defective_barcodes == before["defective_barcodes"]
    assert session.good_barcodes == before["good_barcodes"]
    assert session.current_step == before["current_step"]


def test_product_exchange_completion_requires_target_quantity():
    session = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=2,
        defective_barcodes=["AAA2270730100-BAD-1"],
        good_barcodes=["AAA2270730100-GOOD-1"],
    )

    validation = product_exchange.validate_exchange_completion(session)

    assert validation.status == "error"
    assert "목표 수량" in validation.message
    with pytest.raises(ValueError, match="목표 수량"):
        product_exchange.build_exchange_completion_detail(session)


def test_product_exchange_completion_rejects_same_barcode_on_both_sides():
    session = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        defective_barcodes=["AAA2270730100-SAME"],
        good_barcodes=["AAA2270730100-SAME"],
    )

    validation = product_exchange.validate_exchange_completion(session)

    assert validation.status == "error"
    assert "같은 바코드" in validation.message
    with pytest.raises(ValueError, match="같은 바코드"):
        product_exchange.build_exchange_completion_detail(session)


@pytest.mark.parametrize(
    ("defective_barcodes", "good_barcodes", "expected_message"),
    [
        (["AAA2270730100-BAD", "AAA2270730100-BAD"], ["AAA2270730100-GOOD-1", "AAA2270730100-GOOD-2"], "불량품 바코드"),
        (["AAA2270730100-BAD"], [""], "양품 바코드"),
        (["AAA2270730100-BAD"], [123], "양품 바코드"),
    ],
)
def test_product_exchange_completion_rejects_duplicate_or_non_text_barcodes(
    defective_barcodes,
    good_barcodes,
    expected_message,
):
    session = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=len(defective_barcodes),
        defective_barcodes=defective_barcodes,
        good_barcodes=good_barcodes,
    )

    validation = product_exchange.validate_exchange_completion(session)

    assert validation.status == "error"
    assert expected_message in validation.message
    with pytest.raises(ValueError, match=expected_message):
        product_exchange.build_exchange_completion_detail(session)


def test_product_exchange_completion_rejects_missing_item_code_and_bool_quantity():
    missing_item = product_exchange.ProductExchangeSession(
        item_code="",
        item_name="fixture item",
        target_quantity=1,
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    bool_quantity = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=True,
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )

    assert "품목 코드" in product_exchange.validate_exchange_completion(missing_item).message
    assert "목표 수량" in product_exchange.validate_exchange_completion(bool_quantity).message


def test_product_exchange_completion_rejects_cross_item_barcodes():
    session = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        defective_barcodes=["BBB2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )

    validation = product_exchange.validate_exchange_completion(session)

    assert validation.status == "error"
    assert "품목 코드" in validation.message
    with pytest.raises(ValueError, match="품목 코드"):
        product_exchange.build_exchange_completion_detail(session)


def test_product_exchange_completion_rejects_wrong_state_step():
    session = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        current_step="scan_defective",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )

    validation = product_exchange.validate_exchange_completion(session)

    assert validation.status == "error"
    assert "완료 단계" in validation.message
    with pytest.raises(ValueError, match="완료 단계"):
        product_exchange.build_exchange_completion_detail(session)


def test_complete_exchange_rejects_target_quantity_mismatch(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=2,
        defective_barcodes=["AAA2270730100-BAD-1"],
        good_barcodes=["AAA2270730100-GOOD-1"],
    )
    app._log_event = lambda *args, **kwargs: setattr(app, "logged", True)
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._complete_exchange()

    assert warnings
    assert not hasattr(app, "logged")
    assert not hasattr(app, "destroyed")
    assert app.current_exchange_session.exchange_pairs == []


def test_complete_exchange_rejects_cross_item_barcodes_without_logging(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        defective_barcodes=["BBB2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    app._log_event = lambda *args, **kwargs: setattr(app, "logged", True)
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._complete_exchange()

    assert warnings
    assert "품목 코드" in warnings[0][1]
    assert not hasattr(app, "logged")
    assert not hasattr(app, "destroyed")
    assert app.current_exchange_session.exchange_pairs == []


def test_complete_exchange_rejects_wrong_state_step_without_logging(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        current_step="scan_defective",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    app._log_event = lambda *args, **kwargs: setattr(app, "logged", True)
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._complete_exchange()

    assert warnings
    assert "완료 단계" in warnings[0][1]
    assert not hasattr(app, "logged")
    assert not hasattr(app, "destroyed")
    assert app.current_exchange_session.current_step == "scan_defective"
    assert app.current_exchange_session.exchange_pairs == []


def test_complete_exchange_stops_when_log_write_fails(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    app._log_event = lambda *args, **kwargs: False
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    app.exchange_complete_button = DummyButton()
    infos = []
    errors = []
    monkeypatch.setattr(container_audit_module.messagebox, "showinfo", lambda *args, **kwargs: infos.append(args))
    monkeypatch.setattr(container_audit_module.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))

    app._complete_exchange()

    assert app.current_exchange_session.exchange_pairs == [
        {"defective": "AAA2270730100-BAD", "good": "AAA2270730100-GOOD"}
    ]
    assert errors
    assert infos == []
    assert not hasattr(app, "destroyed")
    assert app.current_exchange_session.current_step != "completed"
    assert app.exchange_complete_button.config_calls == [
        {"state": container_audit_module.tk.DISABLED},
        {"state": container_audit_module.tk.NORMAL},
    ]


def test_complete_exchange_logs_once_for_completed_session(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    logged = []
    app._log_event = lambda *args, **kwargs: logged.append((args, kwargs)) or True
    app.exchange_complete_button = DummyButton()
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    app.exchange_quantity_spin = DummyButton()
    monkeypatch.setattr(container_audit_module.messagebox, "showinfo", lambda *args, **kwargs: None)
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: None)

    app._complete_exchange()
    app._complete_exchange()

    assert len(logged) == 1
    assert logged[0][0][0] == "PRODUCT_EXCHANGE_COMPLETED"
    assert app.current_exchange_session.current_step == "not_started"
    assert app.current_exchange_session.defective_barcodes == []
    assert app.exchange_dialog is None
    assert app.exchange_quantity_spin is None
    assert app.exchange_complete_button.config_calls == [{"state": container_audit_module.tk.DISABLED}]


def test_complete_exchange_resets_session_so_later_cancel_is_not_emitted(monkeypatch):
    app = _headless_app()
    app.current_exchange_session = ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        current_step="scan_good",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    logged = []
    app._log_event = lambda event, detail=None, synchronous=False: logged.append(
        {"event": event, "detail": detail, "synchronous": synchronous}
    ) or True
    app.exchange_complete_button = DummyButton()
    app.exchange_dialog = type("DummyDialog", (), {"destroy": lambda self: setattr(app, "destroyed", True)})()
    monkeypatch.setattr(container_audit_module.messagebox, "showinfo", lambda *args, **kwargs: None)

    app._complete_exchange()
    assert app._cancel_exchange(reason="app_close") is True

    assert [entry["event"] for entry in logged] == ["PRODUCT_EXCHANGE_COMPLETED"]
    assert app.current_exchange_session.current_step == "not_started"
    assert app.exchange_dialog is None


def test_completed_exchange_session_ignores_later_scans():
    session = product_exchange.ProductExchangeSession(
        item_code="AAA2270730100",
        item_name="fixture item",
        target_quantity=1,
        current_step="completed",
        defective_barcodes=["AAA2270730100-BAD"],
        good_barcodes=["AAA2270730100-GOOD"],
    )
    catalog = item_catalog.ItemCatalog([{"Item Code": "AAA2270730100", "Item Name": "fixture item"}])

    result = product_exchange.apply_exchange_scan(
        session,
        "AAA2270730100-GOOD-2",
        item_catalog=catalog,
        item_code_length=12,
    )

    assert result.status == "ignored"
    assert session.good_barcodes == ["AAA2270730100-GOOD"]


def test_worker_registry_lists_only_active_workers_once_sorted(tmp_path):
    registry_path = tmp_path / "worker_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "workers": [
                    {"name": "나작업", "active": False},
                    {"name": "다작업", "active": True},
                    {"name": "가작업", "active": True},
                    {"name": "가작업", "active": True},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    assert WorkerRegistry(str(registry_path)).list_workers() == ["가작업", "다작업"]


def test_worker_registry_skips_malformed_disk_entries(tmp_path):
    registry_path = tmp_path / "worker_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "workers": [
                    {"name": "홍길동", "active": "false"},
                    {"name": "bad/name", "active": True},
                    {"name": " 가작업 ", "active": True},
                    {"name": "다작업", "active": False},
                    {"name": "가작업", "active": True},
                    ["not", "a", "dict"],
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    assert WorkerRegistry(str(registry_path)).list_workers() == ["가작업"]


def test_worker_registry_quarantines_corrupt_registry_before_recreate(tmp_path):
    registry_path = tmp_path / "worker_registry.json"
    registry_path.write_text('{"workers": [', encoding="utf-8")
    registry = WorkerRegistry(str(registry_path))

    assert registry.list_workers() == []
    assert not registry_path.exists()
    quarantined = list(tmp_path.glob("worker_registry.json.bad-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding="utf-8") == '{"workers": ['

    assert registry.register("홍길동") == "홍길동"
    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    assert [entry["name"] for entry in payload["workers"]] == ["홍길동"]


def test_worker_registry_register_rewrites_sanitized_payload(tmp_path):
    registry_path = tmp_path / "worker_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "workers": [
                    {"name": "bad/name", "active": True},
                    {"name": "홍길동", "active": "false"},
                    {"name": "홍길동", "active": False, "created_at": "old"},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    registry = WorkerRegistry(str(registry_path))

    assert registry.register("홍길동") == "홍길동"

    payload = json.loads(registry_path.read_text(encoding="utf-8"))
    assert payload["workers"] == [{"name": "홍길동", "active": True, "created_at": "old"}]
    assert registry.list_workers() == ["홍길동"]


@pytest.mark.parametrize("name", ["", " ", "bad/name", "bad:name", 'bad"name', "bad|name"])
def test_worker_registry_rejects_empty_or_path_unsafe_names(tmp_path, name):
    registry = WorkerRegistry(str(tmp_path / "worker_registry.json"))

    with pytest.raises(ValueError):
        registry.register(name)


def test_parse_new_format_qr_pipe_key_value_payload():
    app = _headless_app()
    payload = "PHS=1|CLC=AAA2270730100|QT=60"

    assert app._parse_new_format_qr(payload) == label_qr.parse_new_format_qr(payload) == {
        "PHS": "1",
        "CLC": "AAA2270730100",
        "QT": "60",
    }


def test_parse_new_format_qr_json_object_payload():
    app = _headless_app()

    assert app._parse_new_format_qr('{"CLC":"AAA2270730100","QT":"60"}') == {
        "CLC": "AAA2270730100",
        "QT": "60",
    }


@pytest.mark.parametrize(
    "payload",
    [
        '{"CLC":"AAA2270730100","CLC":"BBB2270730100","QT":"60"}',
        '{"CLC":"AAA2270730100"," CLC ":"BBB2270730100","QT":"60"}',
        '{"":"AAA2270730100","QT":"60"}',
        '{"  ":"AAA2270730100","QT":"60"}',
    ],
)
def test_parse_new_format_qr_rejects_malformed_json_payloads(payload):
    assert label_qr.parse_new_format_qr(payload) is None


def test_canonical_master_label_key_matches_equivalent_json_pipe_and_base64_payloads():
    encoded = base64.b64encode(b'{"QT":"60","CLC":"AAA2270730100"}').decode("ascii")

    assert label_qr.canonical_master_label_key('{"CLC":"AAA2270730100","QT":"60"}') == label_qr.canonical_master_label_key(
        '{"QT":"60","CLC":"AAA2270730100"}'
    )
    assert label_qr.canonical_master_label_key("QT=60|CLC=AAA2270730100") == label_qr.canonical_master_label_key(
        "CLC=AAA2270730100|QT=60"
    )
    assert label_qr.canonical_master_label_key(encoded) == label_qr.canonical_master_label_key(
        '{"CLC":"AAA2270730100","QT":"60"}'
    )


@pytest.mark.parametrize(
    ("payload", "default", "expected"),
    [
        ({"QT": "60"}, None, 60),
        ({"QT": ""}, 10, 10),
        ({}, 10, 10),
        ({"QT": "0"}, None, None),
        ({"QT": "bad"}, None, None),
    ],
)
def test_parse_positive_quantity(payload, default, expected):
    assert label_qr.parse_positive_quantity(payload, default=default) == expected


def test_replacement_log_lookup_matches_canonical_master_label_identity(tmp_path):
    app = _headless_app()
    log_path = tmp_path / "검사작업이벤트로그_fixture_20260623.csv"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "검사자",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(
                    {
                        "master_label_code": '{"QT":"60","CLC":"AAA2270730100"}',
                        "item_code": "AAA2270730100",
                        "scan_count": 2,
                        "tray_capacity": 60,
                        "product_barcodes": ["BC-1", "BC-2"],
                    },
                    ensure_ascii=False,
                ),
            }
        )

    found = app._find_log_in_file(str(log_path), '{"CLC":"AAA2270730100","QT":"60"}')

    assert found is not None
    assert found["found_row_index"] == 2
    assert found["found_source_byte_offset"] and found["found_source_byte_offset"] > 0
    assert found["original_details"]["product_barcodes"] == ["BC-1", "BC-2"]


def test_replacement_search_skips_original_superseded_from_different_log_file(tmp_path, monkeypatch):
    old_label = '{"QT":"60","CLC":"AAA2270730100"}'
    new_label = '{"QT":"60","CLC":"AAA2270730100","LOT":"NEW"}'
    old_log_path = tmp_path / "이적작업이벤트로그_홍길동_20260622.csv"
    with old_log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-22T09:00:00",
                "worker_name": "홍길동",
                        "event": "TRAY_COMPLETE",
                        "details": json.dumps(
                            {
                                "master_label_code": old_label,
                                "item_code": "AAA2270730100",
                                "product_barcodes": ["AAA2270730100-001"],
                            },
                            ensure_ascii=False,
                        ),
                    }
                )
    app = _headless_app()
    original = app._find_log_in_file(str(old_log_path), old_label)
    assert original is not None
    replacement_detail = event_payloads.build_master_label_replacement_detail(
        original_details=original["original_details"],
        old_label=old_label,
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id=original["found_source_file_id"],
        source_row_number=original["found_row_index"],
        source_byte_offset=original["found_source_byte_offset"],
        operator="홍길동",
        stable_hash_func=event_contracts.stable_hash,
        old_row_hash=original["found_row_hash"],
    )

    replacement_log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    with replacement_log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(replacement_detail, ensure_ascii=False),
            }
        )

    superseded_hashes = replacement_log_lookup.collect_replacement_superseded_hashes(
        [str(replacement_log_path), str(old_log_path)],
        stable_hash_func=event_contracts.stable_hash,
    )
    assert original["found_row_hash"] in superseded_hashes

    app.save_folder = str(tmp_path)
    app.replacement_context = {"old_label": old_label}
    app._compare_quantities_and_proceed = lambda: setattr(app, "compared", True)
    app.cancel_master_label_replacement = lambda: setattr(app, "cancelled", True)
    warnings = []
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))

    app._perform_historical_master_label_swap()

    assert warnings
    assert hasattr(app, "cancelled")
    assert not hasattr(app, "compared")
    assert "found_log_file" not in app.replacement_context


def test_replacement_search_uses_current_transfer_log_prefix(tmp_path, monkeypatch):
    old_label = '{"QT":"60","CLC":"AAA2270730100"}'
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    with log_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(
                    {
                        "master_label_code": old_label,
                        "item_code": "AAA2270730100",
                        "product_barcodes": ["BC-1"],
                    },
                    ensure_ascii=False,
                ),
            }
        )
    app = _headless_app()
    app.save_folder = str(tmp_path)
    app.replacement_context = {"old_label": '{"CLC":"AAA2270730100","QT":"60"}'}
    app._compare_quantities_and_proceed = lambda: setattr(app, "compared", True)
    app.cancel_master_label_replacement = lambda: setattr(app, "cancelled", True)
    monkeypatch.setattr(container_audit_module.messagebox, "showwarning", lambda *args, **kwargs: app.cancel_master_label_replacement())

    app._perform_historical_master_label_swap()

    assert app.compared is True
    assert app.replacement_context["found_log_file"] == str(log_path)
    assert app.replacement_context["original_details"]["product_barcodes"] == ["BC-1"]
    assert not hasattr(app, "cancelled")


@pytest.mark.parametrize("payload", ["AAA2270730100", "[1,2,3]", "{not-json}"])
def test_parse_new_format_qr_rejects_unknown_payloads(payload):
    app = _headless_app()

    assert app._parse_new_format_qr(payload) is None


@pytest.mark.parametrize(
    "payload",
    [
        "CLC=AAA2270730100|BROKEN|QT=60",
        "CLC=AAA2270730100|=bad|QT=60",
        "CLC=AAA2270730100|CLC=BBB2270730100|QT=60",
    ],
)
def test_parse_new_format_qr_rejects_malformed_pipe_payloads(payload):
    assert label_qr.parse_new_format_qr(payload) is None


def test_stable_hash_is_deterministic_across_dict_key_order():
    app = _headless_app()

    assert app._stable_hash({"b": 2, "a": 1}) == app._stable_hash({"a": 1, "b": 2})
    assert app._stable_hash({"a": 1}) == event_contracts.stable_hash({"a": 1})


def test_stable_hash_normalizes_unicode_and_rejects_non_finite_numbers():
    assert event_contracts.stable_hash({"text": "\uac00"}) == event_contracts.stable_hash(
        {"text": "\u1100\u1161"}
    )
    with pytest.raises(ValueError):
        event_contracts.stable_hash({"value": float("nan")})
    with pytest.raises(ValueError):
        event_contracts.stable_hash({"value": float("inf")})


def test_plan_b_event_detail_adds_legacy_dispatch_metadata():
    app = _headless_app()

    enriched = app._plan_b_event_detail("SCAN_OK", {"barcode": "ABC123"})

    assert enriched["barcode"] == "ABC123"
    assert enriched["source_system"] == "container_audit"
    assert enriched["source_transport_or_dataset"] == "legacy_transfer_csv"
    assert enriched["raw_event_name"] == "SCAN_OK"
    assert enriched["canonical_event_name"] == "SCAN_OK"
    assert enriched["dispatch_key"] == "container_audit|legacy_transfer_csv|SCAN_OK"
    assert enriched["identity_class"] == "LEGACY_FALLBACK"
    assert enriched["integrity_requirement"] == "UNSIGNED_LEGACY_ALLOWED"
    assert enriched["integrity_status"] == "UNSIGNED_LEGACY"
    assert enriched["parser_mapping_version"] == "container-audit-plan-b-v1"


def test_plan_b_event_detail_overwrites_caller_supplied_contract_fields():
    app = _headless_app()

    enriched = app._plan_b_event_detail(
        "SCAN_OK",
        {
            "source_system": "custom_source",
            "canonical_event_name": "CUSTOM_SCAN_OK",
            "dispatch_key": "bad",
            "integrity_status": "TRUSTED",
        },
    )

    assert enriched["source_system"] == "container_audit"
    assert enriched["canonical_event_name"] == "SCAN_OK"
    assert enriched["raw_event_name"] == "SCAN_OK"
    assert enriched["dispatch_key"] == "container_audit|legacy_transfer_csv|SCAN_OK"
    assert enriched["integrity_status"] == "UNSIGNED_LEGACY"


def test_plan_b_event_detail_allows_explicit_canonical_alias():
    app = _headless_app()

    enriched = app._plan_b_event_detail(
        "TRAY_RESTORED_FROM_PARK",
        {"master_label_code": "PHS=1|CLC=AAA2270730100|QT=60"},
        canonical_event_name="TRAY_RESTORED",
    )

    assert enriched["raw_event_name"] == "TRAY_RESTORED_FROM_PARK"
    assert enriched["canonical_event_name"] == "TRAY_RESTORED"
    assert enriched["dispatch_key"] == "container_audit|legacy_transfer_csv|TRAY_RESTORED_FROM_PARK"

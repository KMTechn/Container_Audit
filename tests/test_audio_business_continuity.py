"""Audio failures cannot interrupt saved scans, completion, warning or close.

The scan boundary executes the source method's unmodified generator tail;
completion uses the existing real JSON/SQLite/CSV flow with fake Tk/transport.
Every backend is fake, including the healthy control. No native sound runs.
"""
import ast
import builtins
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import Container_Audit as ca
import native_audio
from tests.test_legacy_label_transition import flow, _rows  # noqa: F401

ITEM = "AAA2270730100"
PRIVATE_DETAIL = "synthetic audio detail that must not be published"
PREFIX = "CONTAINER_AUDIT_AUDIO="
pytestmark = pytest.mark.usefixtures("owned_tk_workers")


def _sound(monkeypatch, tmp_path, fault):
    class Backend:
        SND_FILENAME, SND_ASYNC, SND_NODEFAULT, SND_LOOP = 1, 2, 4, 8

        @staticmethod
        def PlaySound(_path, _flags):
            if fault == "exception":
                raise RuntimeError(PRIVATE_DETAIL)

    monkeypatch.setattr(native_audio, "_winsound", None if fault == "missing" else Backend)
    if fault == "sound_object_exception":
        def fail():
            raise OSError(PRIVATE_DETAIL)
        return SimpleNamespace(play=fail)
    wav = tmp_path / "feedback.wav"
    wav.write_bytes(b"RIFF")
    return native_audio.WavSound(wav)


def _records(capsys):
    text = capsys.readouterr().out
    assert PRIVATE_DETAIL not in text
    assert not any(old in text for old in ("완료음 재생 실패", "오류음 재생 실패", "오류음 정지 실패"))
    rows = [json.loads(line[len(PREFIX):]) for line in text.splitlines() if line.startswith(PREFIX)]
    for row in rows:
        assert set(row) == {"code"}
        assert row["code"] in {"AUDIO_INIT_FAILED", "AUDIO_PLAY_FAILED", "AUDIO_STOP_FAILED"}
    return rows


def _scan_tail():
    tree = ast.parse(Path(ca.__file__).read_text(encoding="utf-8"))
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ContainerAudit")
    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "_process_barcode_steps")
    save_index = max(index for index, node in enumerate(method.body)
                     if isinstance(node, ast.Try) and any(
                         isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                         and call.func.attr == "_save_tray_state_snapshot" for call in ast.walk(node)))
    function = ast.parse(
        "def scan_tail(self, tray, epoch, state, raw_barcode, now, interval, "
        "_durable_scan_id, _durable_scan_log, held_audit, _lease_hold_replay=False): pass"
    ).body[0]
    function.body = method.body[save_index:]
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    namespace = dict(vars(ca))
    exec(compile(module, ca.__file__, "exec"), namespace)
    return namespace["scan_tail"]


def _run_saved_scan(sound, held):
    trace = ["held_audit_already_durable"] if held else []
    barcode = ITEM + "-AUDIO-001"
    tray = SimpleNamespace(item_code=ITEM, scanned_barcodes=[barcode], tray_size=1)
    presenter = SimpleNamespace(record_normal_scan=lambda *_: None, clear=lambda: None)
    app = SimpleNamespace(
        current_tray=tray, _scan_callback_epoch=0, success_sound=sound,
        SCAN_CONTRACT_VERSION=ca.ContainerAudit.SCAN_CONTRACT_VERSION,
        _save_tray_state_snapshot=lambda state: trace.append("saved") or True,
        _warning_state_presenter=lambda: presenter, _stop_warning_beep=lambda: None,
        add_scanned_barcode=lambda *_: trace.append("rendered"),
        _preflight_scan_receipts=lambda: {},
        _project_stored_audit_event=lambda *_args, **_kwargs: trace.append("held_projected") or True,
        _log_event=lambda *_args, **_kwargs: trace.append("SCAN_OK") or True,
        complete_tray=lambda: trace.append("completed") or True,
    )
    generator = _scan_tail()(app, tray, 0, {}, barcode, ca.datetime.datetime.now(), 0.1,
                             "held-1" if held else "", held, {"worker_record": {}} if held else None)
    value = None
    while True:
        try:
            operation = generator.send(value)
        except StopIteration as done:
            assert done.value is True
            break
        value = operation()
    assert trace == (["held_audit_already_durable"] if held else []) + [
        "saved", "rendered", "held_projected" if held else "SCAN_OK",
    ] + ([] if held else ["completed"])
    if held:
        assert app._preflight_completion_due is True


@pytest.mark.parametrize("held", [False, True])
@pytest.mark.parametrize("fault", ["ok", "exception", "missing", "sound_object_exception"])
def test_saved_first_scan_reaches_log_projection_and_completion(monkeypatch, tmp_path, capsys, held, fault):
    _run_saved_scan(_sound(monkeypatch, tmp_path, fault), held)
    assert _records(capsys) == ([] if fault == "ok" else [{"code": "AUDIO_PLAY_FAILED"}])


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("fault", ["exception", "missing"])
def test_audio_failure_preserves_full_and_partial_durable_completion(flow, monkeypatch, tmp_path, capsys, partial, fault):
    app = flow(transition=True)
    # Isolate completion feedback from the earlier acceptance feedback.
    app.success_sound = None
    app.error_sound = app.completion_sound = _sound(monkeypatch, tmp_path, fault)
    app._process_barcode_logic(f"CLC={ITEM}|QT={3 if partial else 2}")
    app._process_barcode_logic(ITEM + "-AUDIO-001")
    if partial:
        assert app._complete_current_tray_as_partial() is True
        assert app._short_confirmation_undo is None
        path, = app._short_projection_path("unused").parent.glob("*.json")
        assert path.is_file()
        assert len(_rows(app, 'TRAY_COMPLETE')) == 1
        assert not app.current_tray.master_label_code
    else:
        app._process_barcode_logic(ITEM + "-AUDIO-002")
        assert len(_rows(app, "TRAY_COMPLETE")) == 1
        assert not app.current_tray.master_label_code
    assert {"code": "AUDIO_PLAY_FAILED"} in _records(capsys)


@pytest.mark.parametrize("fault", ["exception", "missing"])
def test_warning_play_and_stop_failures_leave_warning_inactive(monkeypatch, tmp_path, capsys, fault):
    app = SimpleNamespace(error_sound=_sound(monkeypatch, tmp_path, fault))
    ca.ContainerAudit._start_warning_beep(app)
    assert app._warning_beep_active is False
    ca.ContainerAudit._stop_warning_beep(app)
    assert app._warning_beep_active is False
    assert _records(capsys) == [{"code": "AUDIO_PLAY_FAILED"}, {"code": "AUDIO_STOP_FAILED"}]


@pytest.mark.parametrize("fault", ["exception", "missing"])
def test_stop_failure_still_finishes_application_close(monkeypatch, tmp_path, capsys, fault):
    _sound(monkeypatch, tmp_path, fault)
    destroyed = []
    app = SimpleNamespace(_event_log_close_requested=True,
                          log_thread=SimpleNamespace(is_alive=lambda: False),
                          root=SimpleNamespace(destroy=lambda: destroyed.append(True)))
    ca.ContainerAudit._finalize_application_close(app)
    assert destroyed == [True] and app._application_close_complete is True
    assert _records(capsys) == [{"code": "AUDIO_STOP_FAILED"}]


def test_audio_diagnostic_output_failure_does_not_interrupt_saved_scan(monkeypatch, tmp_path):
    sound = _sound(monkeypatch, tmp_path, "exception")

    def unavailable_output(*_args, **_kwargs):
        raise OSError(PRIVATE_DETAIL)

    monkeypatch.setattr(builtins, "print", unavailable_output)
    _run_saved_scan(sound, held=False)

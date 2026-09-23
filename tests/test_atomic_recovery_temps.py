"""Interrupted atomic recovery writes remain owned by their original PHS2 keys."""

from __future__ import annotations

import base64
import csv
import hashlib
import itertools
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from Container_Audit import TraySession
from parked_tray_store import ParkedTrayStore, atomic_temp_target
from preflight_scan_hold import PreflightScanHoldStore
from recovery_file_read import read_recovery_file
from tests.test_container_audit_contracts import _headless_app
from tests.test_container_p0_contracts import _saved_tray_state


def _test_app(tmp_path, monkeypatch):
    app = _headless_app()
    app.parked_trays_dir = str(tmp_path / "parked")
    app.save_folder = str(tmp_path / "events")
    app.CURRENT_TRAY_STATE_FILE = "current.json"
    app.PREFLIGHT_SCAN_HOLD_FILE = "hold.json"
    app.worker_name = "tester"
    app.current_tray = TraySession()
    app.is_idle = False
    app.completed_master_labels = set()
    app.master_label_replace_state = None
    app.COLOR_DANGER = "danger"
    app._intercept_phs_reconciliation_scan = lambda _value: False
    app._intercept_active_tray_phs2_scan = lambda _value: False
    app._is_completed_master_label = lambda _value: False
    app._item_catalog = lambda: SimpleNamespace(find_by_code=lambda _code: {"Item Code": "AAA2270730100"})
    begun = []
    app._begin_compact_phs2_preflight = lambda **kwargs: begun.append(kwargs["barcode"])
    app.show_fullscreen_warning = lambda *_args: None
    monkeypatch.setattr("Container_Audit.messagebox.askyesno", lambda *_a, **_k: False)
    return app, begun


def _paired_record(hold_path: Path, hold_raw: bytes, current_path: Path, current_raw: bytes):
    parts = {}
    for name, path, raw in (("hold", hold_path, hold_raw), ("current", current_path, current_raw)):
        parts[name] = {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest(),
                       "bytes_b64": base64.b64encode(raw).decode("ascii")}
    identity = hashlib.sha256("".join(
        parts[name]["path"] + parts[name]["sha256"] for name in ("hold", "current")
    ).encode("utf-8")).hexdigest()
    return {"schema": "container-audit-paired-preflight-v1", "id": identity,
            "created_at": "2026-09-24T00:00:00Z", **parts}


def _bind_unknown_evidence(tmp_path, evidence_id, labels):
    audit_dir = tmp_path / "local_events"
    audit_dir.mkdir(exist_ok=True)
    with (audit_dir / "binding.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("event", "details"))
        writer.writeheader()
        writer.writerow({"event": "PHS2_AUDIT_EVIDENCE_BOUND",
                         "details": json.dumps({"source_audit_id": evidence_id, "labels": labels})})


@pytest.mark.parametrize("format_name,variant,final_exists", itertools.product(
    ("parked", "parked_recovery", "parked_marker", "current", "hold",
     "pair_record", "pair_release", "pair_marker", "stale_hold", "stale_marker",
     "event_outbox", "label_journal"),
    ("valid", "damaged", "empty"), (False, True),
))
def test_interrupted_atomic_recovery_matrix(
    tmp_path, monkeypatch, format_name, variant, final_exists,
):
    app, begun = _test_app(tmp_path, monkeypatch)
    state = _saved_tray_state()
    label = state["master_label_code"]
    pair_label = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-PAIR|CLC=AAA2270730100|LBL=PAIR|HSH=0123456789abcdef"
    other = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-OTHER|CLC=AAA2270730100|LBL=OTHER|HSH=0123456789abcdef"
    parked = app._parked_store()
    pair = app._paired_preflight_store()
    events = Path(app.save_folder)
    events.mkdir()
    hold_path = events / "hold.json"
    hold_store = PreflightScanHoldStore(hold_path, capacity=68)
    hold_store.start(worker="tester", master_raw=label, scan_epoch=1)
    hold_raw = hold_path.read_bytes()
    hold_path.unlink()
    current_path = events / "current.json"
    paired_current = {**state, "master_label_code": pair_label,
                      "canonical_input_tag_qr": pair_label, "active_label_qr_payload": pair_label,
                      "active_label_id": "PAIR"}
    current_raw = json.dumps(paired_current).encode("utf-8")
    record = _paired_record(hold_path, hold_raw, current_path, current_raw)
    record_path = pair.directory / record["id"] / "record.json"
    source = parked.deterministic_label_path(worker_name="tester", master_label=label)
    assert source is not None
    marker = parked.manager_hold_path(source)
    stale = pair.directory / "stale-current-test.json"
    payloads = {
        "parked": (source, state),
        "parked_recovery": (parked.directory / "parked_recovery_tester_0123456789abcdef.json", state),
        "parked_marker": (marker, {"schema": "container-audit-parked-manager-hold-v1",
                                   "label": label, "source_sha256": "a" * 64}),
        "current": (current_path, state),
        "hold": (hold_path, json.loads(hold_raw)),
        "pair_record": (record_path, record),
        "pair_release": (record_path.parent / "released.json", {"id": record["id"]}),
        "pair_marker": (record_path.parent / "manager-hold.json",
                        {"schema": "container-audit-paired-manager-hold-v1", "labels": [label, pair_label]}),
        "stale_hold": (stale, {"schema": "container-audit-stale-current-hold-v1",
                               "labels": [label], "original_sha256": "a" * 64,
                               "changed_sha256": "b" * 64}),
        "stale_marker": (pair.stale_manager_path(stale),
                         {"schema": "container-audit-paired-manager-hold-v1",
                          "labels": [label, pair_label], "source_sha256": "a" * 64}),
        "event_outbox": (events / "_event_outbox" / ("1" * 20 + "-" + "b" * 32 + ".json"),
                         {"log_file_path": str(events / "audit.csv"),
                          "log_entry": {"event": "TRAY_PARKED", "details": json.dumps(
                              {"snapshot": {"master_label_code": label}}, ensure_ascii=False)}}),
        "label_journal": (tmp_path / "phs_label_exchange" / "phs_label_exchange_recovery.json",
                          {"schema_version": "container-audit-phs-label-exchange-v1",
                           "state": {"source_label": label, "target_label": pair_label}}),
    }
    target, payload = payloads[format_name]
    target.parent.mkdir(parents=True, exist_ok=True)
    if format_name in {"pair_release", "pair_marker"}:
        record_path.write_text(json.dumps(record), encoding="utf-8")
    if variant == "damaged":
        payload = dict(payload)
        if format_name == "event_outbox":
            payload["log_entry"] = "broken"
        else:
            payload["schema"] = "broken"
    raw = b"" if variant == "empty" else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    temp = target.with_name(target.name + (".abc12345.tmp" if format_name == "label_journal"
                                           else ".123." + "a" * 32 + ".tmp"))
    temp.write_bytes(raw)
    if final_exists:
        target.write_bytes(json.dumps(payloads[format_name][1], ensure_ascii=False).encode("utf-8"))
    assert atomic_temp_target(temp) == target
    if variant == "valid":
        recovery_kind = ("parked_manager_hold" if format_name == "parked_marker" else
                         "parked" if format_name.startswith("parked") else
                         "current" if format_name == "current" else
                         "hold" if format_name == "hold" else
                         "record" if format_name == "pair_record" else
                         "released" if format_name == "pair_release" else
                         "manager_hold" if format_name in {"pair_marker", "stale_marker"} else
                         "json" if format_name in {"event_outbox", "label_journal"} else "stale_hold")
        assert read_recovery_file(temp, recovery_kind).verified

    evidence = parked.enumerate_key_evidence(pair_store=pair)
    row = next(row for row in evidence if row.path == temp)
    assert row.kind == ("parked_temp" if format_name.startswith("parked") else "atomic_temp")
    assert row.binds(label)
    if final_exists:
        assert "최종 파일 있음" in row.problem
    else:
        assert not target.exists()
    app._process_barcode_logic(label)
    assert label not in begun
    if row.unidentified:
        if row.kind == "parked_temp":
            parked.bind_invalid_label(temp, label)
        else:
            _bind_unknown_evidence(tmp_path, row.evidence_id,
                                   [label, pair_label] if format_name == "pair_record" else [label])
    else:
        if row.kind == "parked_temp":
            parked.bind_invalid_label(temp, label)
    rebound = next(row for row in parked.enumerate_key_evidence(pair_store=pair) if row.path == temp)
    assert not rebound.unidentified
    app._process_barcode_logic(other)
    assert other in begun, (app._paired_preflight_blocks_label(other),
                            parked.existing_label_path_any_worker(master_label=other),
                            [(item.kind, item.unidentified, item.labels, item.digest, item.problem)
                             for item in parked.enumerate_key_evidence(pair_store=pair)])
    app._process_barcode_logic(label)
    assert label not in begun
    assert temp.read_bytes() == raw
    if final_exists:
        assert target.read_bytes() == json.dumps(payloads[format_name][1], ensure_ascii=False).encode("utf-8")
        audited = []
        app._log_event = lambda event, **kwargs: audited.append((event, kwargs)) or True
        app._audit_recovered_atomic_temps(evidence)
        assert len(audited) == 1
        assert audited[0][0] == "PHS2_ATOMIC_TEMP_QUARANTINED"
        assert audited[0][1]["synchronous"] is True
        assert temp.read_bytes() == raw


def test_atomic_parked_probe_survives_without_final_and_manager_defers(tmp_path, monkeypatch):
    app, begun = _test_app(tmp_path, monkeypatch)
    state = _saved_tray_state()
    label = state["master_label_code"]
    store = app._parked_store()
    source = store.deterministic_label_path(worker_name="tester", master_label=label)
    source.parent.mkdir(parents=True)
    temp = source.with_name(source.name + ".123." + "b" * 32 + ".tmp")
    temp.write_text(json.dumps(state), encoding="utf-8")
    original = temp.read_bytes()
    assert read_recovery_file(temp, "parked").verified
    app._process_barcode_logic(label)
    assert not begun
    assert any(row.path == temp and row.problem for row in store.scan_for_worker("tester", strict=True))
    store.bind_invalid_label(temp, label)
    assert store.manager_hold_path(temp).exists()
    assert temp.read_bytes() == original


def test_parked_temp_retains_filename_and_content_keys(tmp_path):
    state = _saved_tray_state()
    filename_label = state["master_label_code"]
    content_label = "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-CONTENT|CLC=AAA2270730100|LBL=CONTENT|HSH=0123456789abcdef"
    store = ParkedTrayStore(tmp_path)
    target = store.deterministic_label_path(worker_name="tester", master_label=filename_label)
    target.parent.mkdir(exist_ok=True)
    temp = target.with_name(target.name + ".123." + "a" * 32 + ".tmp")
    state.update(master_label_code=content_label, canonical_input_tag_qr=content_label,
                 active_label_qr_payload=content_label, active_label_id="CONTENT")
    temp.write_text(json.dumps(state), encoding="utf-8")
    row = next(item for item in store.enumerate_key_evidence() if item.path == temp)
    assert row.binds(filename_label) and row.binds(content_label)
    assert not row.unidentified


def test_manager_can_bind_unknown_current_temp_without_changing_original(tmp_path, monkeypatch):
    app, _ = _test_app(tmp_path, monkeypatch)
    label = _saved_tray_state()["master_label_code"]
    path = Path(app.save_folder) / ("current.json.123." + "a" * 32 + ".tmp")
    path.parent.mkdir()
    path.write_bytes(b"")
    original = path.read_bytes()
    row = next(item for item in app._parked_store().enumerate_key_evidence(
        pair_store=app._paired_preflight_store(),
    ) if item.path == path)
    assert row.unidentified
    audit_dir = tmp_path / "local_events"
    audit_dir.mkdir()
    with (audit_dir / "quarantine.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("event", "details"))
        writer.writeheader()
        writer.writerow({"event": "PHS2_ATOMIC_TEMP_QUARANTINED",
                         "details": json.dumps({"source_file": path.name,
                                                "source_sha256": row.content_sha256,
                                                "labels": []})})
    app.root = SimpleNamespace()
    app._blocked_work_identity_matches = lambda _approval: True
    app._blocked_work_identity_is_current = lambda _approval: True
    app._blocked_work_audit_identity = lambda _approval: {"actor": "manager"}
    app._transfer_seal_runtime = lambda: SimpleNamespace(client=SimpleNamespace(
        authority_scope_id="scope", resolve_phs_label=lambda **_kwargs: {"id": "known"},
    ))
    app._log_event = lambda _event, **kwargs: _bind_unknown_evidence(tmp_path, row.evidence_id, kwargs["detail"]["labels"]) or True
    tasks = []
    app._ui_task_lane = lambda: SimpleNamespace(is_busy=lambda: False, submit=tasks.append)
    monkeypatch.setattr("Container_Audit.messagebox.showinfo", lambda *_a, **_k: None)
    app._identify_unreadable_audit(row.evidence_id, {"actor": "manager"}, known_labels=(label,))
    assert len(tasks) == 1
    tasks[0].finish(tasks[0].work())
    rebound = next(item for item in app._parked_store().enumerate_key_evidence(
        pair_store=app._paired_preflight_store(),
    ) if item.path == path)
    assert rebound.labels == (label,)
    audit = [item for item in app._parked_store().enumerate_key_evidence(
        pair_store=app._paired_preflight_store(),
    ) if item.kind == "audit" and item.problem == "PHS2_ATOMIC_TEMP_QUARANTINED"]
    assert len(audit) == 1 and audit[0].labels == (label,)
    assert path.read_bytes() == original

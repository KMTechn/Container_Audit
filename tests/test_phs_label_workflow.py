import datetime
import inspect
from pathlib import Path

import pytest

from Container_Audit import ContainerAudit, TraySession
from phs_label_workflow import (
    PHSLabelExchangeCoordinator,
    PHSLabelExchangeJournal,
    PHSLabelRenderer,
    PHSPhysicalPrintError,
    PhysicalPrintEvidence,
    RenderedPHSLabel,
)
from transfer_seal import (
    TransferSealError,
    membership_hash,
    validate_compact_phs2_preflight,
)
import tray_state


SCOPE = "PLANT-01"
ITEM = "AAA2270730100"
INPUT_TAG = "ITAG-001"
ROOT_LABEL = "INPUT-LABEL-001"
ROOT_HASH = "a" * 64
ROOT_PREFIX = ROOT_HASH[:16]
ACTIVE_LABEL = "PHSL-ACTIVE-002"
ACTIVE_HASH = "c" * 64
ACTIVE_PREFIX = ACTIVE_HASH[:16]
TARGET_LABEL = "PHSL-TARGET-003"
TARGET_HASH = "d" * 64
TARGET_PREFIX = TARGET_HASH[:16]
TARGET_DATE = "2026-07-29"
TARGET_INSTRUCTION = "PHS-INSTRUCTION-NEW"


def _qr(label_id=ROOT_LABEL, hash_prefix=ROOT_PREFIX):
    return (
        f"PHS=2|SRC=KMTECH_INPUT_TAG|ITG={INPUT_TAG}|CLC={ITEM}|"
        f"LBL={label_id}|HSH={hash_prefix}"
    )


def _label(
    label_id,
    hash_prefix,
    *,
    state="ACTIVE",
    business_date="2026-07-28",
    worker_code="AAA2270730100-001",
    label_version=1,
    membership_version=1,
):
    return {
        "label_id": label_id,
        "qr_payload": _qr(label_id, hash_prefix),
        "label_instance_hash": (
            ROOT_HASH if label_id == ROOT_LABEL else ACTIVE_HASH
        ),
        "hash_prefix": hash_prefix,
        "scan_anchor_input_tag_id": INPUT_TAG,
        "item_id": ITEM,
        "business_date": business_date,
        "worker_code": worker_code,
        "instruction_id": "PHS-INSTRUCTION-OLD",
        "state": state,
        "label_version": label_version,
        "membership_version": membership_version,
        "member_count": 2,
        "membership_hash": membership_hash(("unit-1", "unit-2")),
    }


def _resolved(
    *,
    scan_label=None,
    resolution_kind="OVERLAY_ACTIVE",
    effective=None,
    status="ACTIVE",
):
    members = [
        {
            "unit_id": f"unit-{index}",
            "normalized_barcode": f"{ITEM}-SERIAL-{index}",
            "inbound_iin": "ORIGIN-IIN",
            "current_inbound_iin": "IIN-001",
            "item_id": ITEM,
            "uom": "EA",
            "unit_state": "AVAILABLE",
            "location_code": "PHS_GOOD",
        }
        for index in (1, 2)
    ]
    member_ids = [value["unit_id"] for value in members]
    barcodes = [value["normalized_barcode"] for value in members]
    scan_label = dict(scan_label or _label(ROOT_LABEL, ROOT_PREFIX))
    effective = [dict(value) for value in (effective or [scan_label])]
    return {
        "candidate_count": 1,
        "bundle": {
            "authority_scope_id": SCOPE,
            "authority_epoch": 7,
            "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 3,
            "bundle_id": "PHS-SERVER-001",
            "bundle_role": "TRANSFER_SOURCE",
            "bundle_type": "PHS",
            "bundle_state": "AVAILABLE",
            "external_label": _qr(),
            "source_session_id": INPUT_TAG,
            "item_id": ITEM,
            "uom": "EA",
            "source_iin": "IIN-001",
            "current_location": "PHS_GOOD",
            "current_locations": ["PHS_GOOD"],
            "member_ids": member_ids,
            "member_count": 2,
            "membership_hash": membership_hash(member_ids),
            "barcode_member_count": 2,
            "barcode_membership_hash": membership_hash(barcodes),
            "entity_version": 4,
            "members": members,
        },
        "input_tag": {
            "input_tag_id": INPUT_TAG,
            "label_id": ROOT_LABEL,
            "item_id": ITEM,
            "tag_core_hash": "b" * 64,
            "label_instance_hash": ROOT_HASH,
            "hash_prefix": ROOT_PREFIX,
            "lifecycle": "INSPECTION_COMPLETED",
            "qr_payload": _qr(),
            "session_entity_version": 5,
        },
        "phs_label_resolution": {
            "status": status,
            "resolution": resolution_kind,
            "authority_scope_id": SCOPE,
            "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 3,
            "scanned_label": scan_label,
            "effective_labels": effective,
            "effective_qr_payloads": [
                value["qr_payload"] for value in effective
            ],
        },
    }


def _target_candidate(**updates):
    value = {
        "instruction_id": TARGET_INSTRUCTION,
        "business_date": TARGET_DATE,
        "item_id": ITEM,
        "uom": "Pcs",
        "target_qty_pcs": 2,
        "display_item_code": ITEM,
        "item_daily_ordinal": 2,
        "worker_code": f"{ITEM}-002",
        "state": "PLANNED",
        "entity_version": 3,
    }
    value.update(updates)
    return value


def _target_label(**updates):
    value = {
        "label_id": TARGET_LABEL,
        "qr_payload": _qr(TARGET_LABEL, TARGET_PREFIX),
        "label_instance_hash": TARGET_HASH,
        "hash_prefix": TARGET_PREFIX,
        "scan_anchor_input_tag_id": INPUT_TAG,
        "item_id": ITEM,
        "business_date": TARGET_DATE,
        "worker_code": f"{ITEM}-002",
        "instruction_id": TARGET_INSTRUCTION,
        "state": "PENDING_ACTIVATION",
        "label_version": 1,
        "membership_version": 1,
        "member_count": 2,
        "membership_hash": membership_hash(("unit-1", "unit-2")),
    }
    value.update(updates)
    return value


class FakeRenderer:
    def __init__(self):
        self.calls = 0

    def render(self, _tray, _target):
        self.calls += 1
        return RenderedPHSLabel("label.png", "e" * 64)


class FakePrinter:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.calls = 0

    def print_png(self, _path, *, document_name):
        self.calls += 1
        if self.fail:
            raise PHSPhysicalPrintError("printer offline")
        return PhysicalPrintEvidence(
            printer_name="Default",
            spool_job_id=41,
            document_name=document_name,
            submitted_at="2026-07-28T00:00:00Z",
        )


class FakeCentral:
    def __init__(
        self,
        *,
        fail_prepare_ack_once=False,
        fail_complete_ack_once=False,
        fail_activate_ack_once=False,
        wrong_target=False,
    ):
        self.fail_prepare_ack_once = fail_prepare_ack_once
        self.fail_complete_ack_once = fail_complete_ack_once
        self.fail_activate_ack_once = fail_activate_ack_once
        self.wrong_target = wrong_target
        self.exchange_state = ""
        self.exchange_version = 1
        self.prepare_calls = []
        self.prepare_write_count = 0
        self.print_calls = []
        self.complete_calls = []
        self.activate_calls = []

    def resolve_source(self, _identity):
        return _resolved()

    def list_phs_work_instruction_candidates(self, **kwargs):
        candidate = _target_candidate()
        return {
            **kwargs,
            "uom": "Pcs",
            "status": "MATCH",
            "candidate_count": 1,
            "candidates": [candidate],
        }

    def adopt_phs_label(self, **_kwargs):
        raise AssertionError("overlay source must not be adopted")

    def _projection(self):
        target = _target_label(
            business_date=(
                "2026-07-30" if self.wrong_target else TARGET_DATE
            ),
            state=(
                "ACTIVE"
                if self.exchange_state == "COMMITTED"
                else "PENDING_ACTIVATION"
            ),
        )
        return {
            "status": self.exchange_state,
            "exchange": {
                "exchange_id": "EXCHANGE-1",
                "exchange_kind": "SINGLE",
                "state": self.exchange_state,
                "entity_version": self.exchange_version,
            },
            "source_labels": [
                _label(
                    ROOT_LABEL,
                    ROOT_PREFIX,
                    state=(
                        "SUPERSEDED"
                        if self.exchange_state == "COMMITTED"
                        else "ACTIVE"
                    ),
                )
            ],
            "target_labels": [target],
        }

    def prepare_phs_label_exchange(self, **kwargs):
        self.prepare_calls.append(dict(kwargs))
        if not self.exchange_state:
            self.prepare_write_count += 1
            self.exchange_state = "PREPARED"
            self.exchange_version = 1
        if self.fail_prepare_ack_once:
            self.fail_prepare_ack_once = False
            raise RuntimeError("lost prepare ACK")
        return self._projection()

    def get_phs_label_exchange(self, _exchange_id, **_kwargs):
        return self._projection()

    def request_phs_label_print(self, _exchange_id, **kwargs):
        self.print_calls.append(dict(kwargs))
        self.exchange_state = "PRINTING"
        return {
            "print_attempt": {
                "print_attempt_id": "PRINT-1",
                "label_id": TARGET_LABEL,
                "state": "REQUESTED",
            },
            "exchange": self._projection()["exchange"],
        }

    def complete_phs_label_print(
        self, print_attempt_id, *, succeeded, **kwargs
    ):
        self.complete_calls.append(
            {
                "print_attempt_id": print_attempt_id,
                "succeeded": succeeded,
                **kwargs,
            }
        )
        if succeeded:
            self.exchange_state = "READY"
            self.exchange_version = 2
            response = {
                "print_attempt": {
                    "print_attempt_id": print_attempt_id,
                    "label_id": TARGET_LABEL,
                    "state": "SUCCEEDED",
                },
                "exchange": self._projection()["exchange"],
            }
            if self.fail_complete_ack_once:
                self.fail_complete_ack_once = False
                raise RuntimeError("lost complete ACK")
            return response
        return {
            "print_attempt": {
                "print_attempt_id": print_attempt_id,
                "label_id": TARGET_LABEL,
                "state": "FAILED",
            },
            "exchange": self._projection()["exchange"],
        }

    def activate_phs_label_exchange(self, _exchange_id, **kwargs):
        self.activate_calls.append(dict(kwargs))
        self.exchange_state = "COMMITTED"
        self.exchange_version = 3
        response = self._projection()
        if self.fail_activate_ack_once:
            self.fail_activate_ack_once = False
            raise RuntimeError("lost activate ACK")
        return response


def _tray():
    started = datetime.datetime(2026, 7, 28, 9, 0, 0)
    return TraySession(
        master_label_code=_qr(),
        canonical_input_tag_qr=_qr(),
        active_label_qr_payload=_qr(),
        active_label_id=ROOT_LABEL,
        active_label_business_date="2026-07-28",
        active_label_worker_code=f"{ITEM}-001",
        item_code=ITEM,
        item_name="fixture",
        scanned_barcodes=[f"{ITEM}-SERIAL-1"],
        scan_times=[started + datetime.timedelta(seconds=5)],
        tray_size=2,
        stopwatch_seconds=13.0,
        start_time=started,
    )


def _coordinator(tmp_path, client, printer=None, renderer=None):
    return PHSLabelExchangeCoordinator(
        PHSLabelExchangeJournal(tmp_path / "recovery.json"),
        client,
        renderer=renderer or FakeRenderer(),
        printer=printer or FakePrinter(),
    )


def test_overlay_replaced_scan_uses_one_active_successor_and_keeps_canonical():
    old = _label(ROOT_LABEL, ROOT_PREFIX, state="SUPERSEDED")
    active = _label(ACTIVE_LABEL, ACTIVE_PREFIX)
    resolved = _resolved(
        scan_label=old,
        resolution_kind="OVERLAY_REPLACED",
        effective=[active],
        status="REPLACED",
    )

    result = validate_compact_phs2_preflight(
        parse_fields(_qr()), resolved
    )

    assert result.canonical_input_tag_qr == _qr()
    assert result.input_tag_label_id == ROOT_LABEL
    assert result.active_label_qr_payload == _qr(
        ACTIVE_LABEL, ACTIVE_PREFIX
    )
    assert result.active_label_id == ACTIVE_LABEL
    assert result.replaced_scan is True


def test_overlay_active_successor_scan_resolves_to_immutable_root():
    active = _label(ACTIVE_LABEL, ACTIVE_PREFIX)
    resolved = _resolved(
        scan_label=active,
        resolution_kind="OVERLAY_ACTIVE",
        effective=[active],
        status="ACTIVE",
    )

    result = validate_compact_phs2_preflight(
        parse_fields(_qr(ACTIVE_LABEL, ACTIVE_PREFIX)), resolved
    )

    assert result.canonical_input_tag_qr == _qr()
    assert result.active_label_id == ACTIVE_LABEL
    assert result.replaced_scan is False


@pytest.mark.parametrize(
    ("resolution_kind", "status", "effective", "expected_code"),
    [
        (
            "OVERLAY_NOT_ACTIVE",
            "PENDING_ACTIVATION",
            [_label(ROOT_LABEL, ROOT_PREFIX)],
            "PHS2_LABEL_NOT_ACTIVE",
        ),
        (
            "OVERLAY_REPLACED",
            "REPLACED",
            [
                _label(ACTIVE_LABEL, ACTIVE_PREFIX),
                _label("PHSL-OTHER", "f" * 16),
            ],
            "PHS2_ACTIVE_LABEL_AMBIGUOUS",
        ),
    ],
)
def test_overlay_pending_or_ambiguous_fails_closed(
    resolution_kind, status, effective, expected_code
):
    scanned = (
        _label("PHSL-PENDING", "e" * 16, state="PENDING_ACTIVATION")
        if resolution_kind == "OVERLAY_NOT_ACTIVE"
        else _label(ROOT_LABEL, ROOT_PREFIX, state="SUPERSEDED")
    )
    resolved = _resolved(
        scan_label=scanned,
        resolution_kind=resolution_kind,
        effective=effective,
        status=status,
    )

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_preflight(
            parse_fields(scanned["qr_payload"]), resolved
        )

    assert exc_info.value.code == expected_code


def test_mid_session_exchange_preserves_exact_local_tray_state(tmp_path):
    tray = _tray()
    client = FakeCentral()
    coordinator = _coordinator(tmp_path, client)
    tray_object = id(tray)
    scans_object = id(tray.scanned_barcodes)
    before = {
        "scanned": list(tray.scanned_barcodes),
        "scan_times": list(tray.scan_times),
        "tray_size": tray.tray_size,
        "item_code": tray.item_code,
        "stopwatch": tray.stopwatch_seconds,
        "start_time": tray.start_time,
    }
    persisted = []

    result = coordinator.execute_single(
        tray,
        _target_candidate(),
        persist_tray=lambda: persisted.append(True) or True,
    )

    assert result.success is True
    assert id(tray) == tray_object
    assert id(tray.scanned_barcodes) == scans_object
    assert tray.master_label_code == _qr()
    assert tray.canonical_input_tag_qr == _qr()
    assert tray.active_label_qr_payload == _qr(TARGET_LABEL, TARGET_PREFIX)
    assert tray.active_label_business_date == TARGET_DATE
    assert tray.active_label_worker_code == f"{ITEM}-002"
    assert list(tray.scanned_barcodes) == before["scanned"]
    assert list(tray.scan_times) == before["scan_times"]
    assert tray.tray_size == before["tray_size"]
    assert tray.item_code == before["item_code"]
    assert tray.stopwatch_seconds == before["stopwatch"]
    assert tray.start_time == before["start_time"]
    assert persisted == [True]
    assert client.prepare_write_count == 1
    assert len(client.activate_calls) == 1


def test_print_failure_keeps_old_label_and_never_activates(tmp_path):
    tray = _tray()
    client = FakeCentral()
    printer = FakePrinter(fail=True)
    coordinator = _coordinator(tmp_path, client, printer=printer)

    result = coordinator.execute_single(tray, _target_candidate())

    assert result.success is False
    assert result.status == "PRINT_FAILED"
    assert result.error_code == "LOCAL_PRINTER_ERROR"
    assert tray.master_label_code == _qr()
    assert tray.active_label_qr_payload == _qr()
    assert client.activate_calls == []
    assert client.complete_calls[-1]["succeeded"] is False


def test_replaced_scan_successor_remains_local_source_when_new_print_fails(
    tmp_path,
):
    class SuccessorCentral(FakeCentral):
        def resolve_source(self, _identity):
            return _resolved(
                scan_label=_label(
                    ROOT_LABEL,
                    ROOT_PREFIX,
                    state="SUPERSEDED",
                ),
                resolution_kind="OVERLAY_REPLACED",
                effective=[_label(ACTIVE_LABEL, ACTIVE_PREFIX)],
                status="REPLACED",
            )

        def _projection(self):
            projection = super()._projection()
            projection["source_labels"] = [
                _label(
                    ACTIVE_LABEL,
                    ACTIVE_PREFIX,
                    state=(
                        "SUPERSEDED"
                        if self.exchange_state == "COMMITTED"
                        else "ACTIVE"
                    ),
                )
            ]
            return projection

    tray = _tray()
    client = SuccessorCentral()
    coordinator = _coordinator(
        tmp_path,
        client,
        printer=FakePrinter(fail=True),
    )

    result = coordinator.execute_single(tray, _target_candidate())

    assert result.success is False
    assert result.error_code == "LOCAL_PRINTER_ERROR"
    assert tray.master_label_code == _qr()
    assert tray.active_label_qr_payload == _qr(
        ACTIVE_LABEL,
        ACTIVE_PREFIX,
    )
    assert tray.active_label_id == ACTIVE_LABEL
    assert client.activate_calls == []


def test_prepare_lost_ack_replay_writes_once_and_activate_lost_ack_is_read_back(
    tmp_path,
):
    tray = _tray()
    client = FakeCentral(
        fail_prepare_ack_once=True,
        fail_activate_ack_once=True,
    )
    coordinator = _coordinator(tmp_path, client)

    first = coordinator.execute_single(tray, _target_candidate())
    second = coordinator.execute_single(tray, _target_candidate())

    assert first.status == "PREPARE_PENDING"
    assert first.success is False
    assert second.success is True
    assert client.prepare_write_count == 1
    assert len({call["idempotency_key"] for call in client.prepare_calls}) == 1
    assert len(client.activate_calls) == 1
    assert coordinator.recover_for_tray(tray) is None


def test_known_uncommitted_prepare_rejection_cancels_local_journal(tmp_path):
    tray = _tray()
    client = FakeCentral()

    def reject_prepare(**_kwargs):
        raise TransferSealError(
            "PHS_SOURCE_VERSION_CONFLICT",
            "source changed",
            committed=False,
        )

    client.prepare_phs_label_exchange = reject_prepare
    coordinator = _coordinator(tmp_path, client)

    result = coordinator.execute_single(tray, _target_candidate())

    assert result.success is False
    assert result.error_code == "PHS_SOURCE_VERSION_CONFLICT"
    assert result.status == "CANCELLED"
    assert coordinator.journal.load()["status"] == "CANCELLED"
    assert client.print_calls == []
    assert client.activate_calls == []


def test_restart_recovery_after_print_complete_lost_ack_does_not_reprint(
    tmp_path,
):
    tray = _tray()
    client = FakeCentral(fail_complete_ack_once=True)
    printer = FakePrinter()
    renderer = FakeRenderer()
    first = _coordinator(
        tmp_path, client, printer=printer, renderer=renderer
    )

    interrupted = first.execute_single(tray, _target_candidate())
    restarted = _coordinator(
        tmp_path, client, printer=printer, renderer=renderer
    )
    recovered = restarted.recover_for_tray(tray)

    assert interrupted.status == "PRINT_COMPLETE_PENDING"
    assert interrupted.success is False
    assert recovered is not None and recovered.success is True
    assert printer.calls == 1
    assert renderer.calls == 1
    assert client.prepare_write_count == 1
    assert len(client.activate_calls) == 1
    assert tray.active_label_id == TARGET_LABEL


def test_uncertain_spool_requires_explicit_reprint_confirmation(tmp_path):
    tray = _tray()
    client = FakeCentral()
    printer = FakePrinter()
    renderer = FakeRenderer()
    coordinator = _coordinator(
        tmp_path,
        client,
        printer=printer,
        renderer=renderer,
    )
    original_save = coordinator.journal.save
    failed_once = False

    def fail_first_spool_evidence_save(state):
        nonlocal failed_once
        if (
            not failed_once
            and str(state.get("status") or "") == "LOCAL_PRINT_SUCCEEDED"
        ):
            failed_once = True
            raise OSError("journal disk unavailable")
        return original_save(state)

    coordinator.journal.save = fail_first_spool_evidence_save
    interrupted = coordinator.execute_single(tray, _target_candidate())
    coordinator.journal.save = original_save
    automatic = coordinator.recover_for_tray(tray)
    confirmed = coordinator.execute_single(
        tray,
        _target_candidate(),
        confirm_ambiguous_reprint=True,
    )

    assert interrupted.error_code == "PHS_LOCAL_PRINT_JOURNAL_UNCERTAIN"
    assert automatic is not None
    assert (
        automatic.error_code
        == "PHS_PRINT_REPRINT_CONFIRMATION_REQUIRED"
    )
    assert confirmed.success is True
    assert printer.calls == 2
    assert renderer.calls == 2
    assert len(client.activate_calls) == 1


def test_incomplete_journal_for_another_tray_is_never_overwritten(tmp_path):
    client = FakeCentral()
    coordinator = _coordinator(tmp_path, client)
    coordinator.journal.save(
        {
            "status": "PREPARE_PENDING",
            "canonical_input_tag_qr": _qr(),
        }
    )
    other_tray = _tray()
    other_tray.master_label_code = _qr().replace(INPUT_TAG, "ITAG-OTHER")
    other_tray.canonical_input_tag_qr = other_tray.master_label_code
    other_tray.active_label_qr_payload = other_tray.master_label_code

    result = coordinator.execute_single(other_tray, _target_candidate())
    journal = coordinator.journal.load()

    assert result.success is False
    assert result.error_code == "PHS_LABEL_RECOVERY_CONFLICT"
    assert journal["canonical_input_tag_qr"] == _qr()
    assert client.prepare_calls == []


def test_wrong_target_projection_blocks_before_print_or_activation(tmp_path):
    tray = _tray()
    client = FakeCentral(wrong_target=True)
    coordinator = _coordinator(tmp_path, client)

    result = coordinator.execute_single(tray, _target_candidate())

    assert result.success is False
    assert result.error_code == "PHS_TARGET_LABEL_INVALID"
    assert client.print_calls == []
    assert client.activate_calls == []
    assert tray.active_label_id == ROOT_LABEL


def test_tray_state_migrates_old_phs2_and_validates_active_anchor():
    tray = _tray()
    state = tray_state.tray_session_to_state(tray, worker_name="홍길동")
    legacy_state = {
        key: value
        for key, value in state.items()
        if not key.startswith("active_label_")
        and key != "canonical_input_tag_qr"
    }

    tray_state.validate_tray_state(legacy_state, default_tray_size=60)
    restored = tray_state.tray_session_from_state(
        legacy_state,
        session_factory=TraySession,
        default_tray_size=60,
    )

    assert restored.canonical_input_tag_qr == restored.master_label_code
    assert restored.active_label_qr_payload == restored.master_label_code
    assert restored.active_label_id == ROOT_LABEL

    state["active_label_qr_payload"] = state[
        "active_label_qr_payload"
    ].replace(INPUT_TAG, "OTHER-INPUT-TAG")
    with pytest.raises(tray_state.TrayStateValidationError):
        tray_state.validate_tray_state(state, default_tray_size=60)


def test_qrcode_is_declared_for_packaged_renderer():
    requirements = (
        Path(__file__).resolve().parents[1] / "requirements.txt"
    ).read_text(encoding="utf-8")
    assert any(
        line.strip().lower().split("[", 1)[0].split("=", 1)[0] == "qrcode"
        for line in requirements.splitlines()
    )


def test_real_renderer_writes_date_partitioned_png(tmp_path):
    rendered = PHSLabelRenderer(tmp_path).render(_tray(), _target_label())
    output = Path(rendered.path)

    assert output.is_file()
    assert output.suffix.lower() == ".png"
    assert TARGET_DATE in output.parts
    assert len(rendered.sha256) == 64
    assert output.stat().st_size > 0


def test_ui_keeps_fixed_exchange_button_and_f8_shortcut():
    center_source = inspect.getsource(ContainerAudit._create_center_content)
    init_source = inspect.getsource(ContainerAudit.__init__)

    assert 'text="현품표 교체"' in center_source
    assert "command=self._on_phs_label_exchange_shortcut" in center_source
    assert "'<F8>'" in init_source
    assert "'<Shift-F8>'" in init_source


def parse_fields(payload):
    return {
        segment.split("=", 1)[0]: segment.split("=", 1)[1]
        for segment in payload.split("|")
    }

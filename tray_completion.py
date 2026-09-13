"""Tray completion orchestration for the existing ContainerAudit owner.

The owner keeps scanner admission, recovery and durable execution. These
functions preserve its generator order and separate final state from notice.
"""
import datetime
import hashlib
from pathlib import Path
import tkinter as tk
from typing import Any, Callable, Dict, Mapping, Optional

from event_payloads import build_tray_complete_detail
from protected_admin import persistent_operator_name
from tk_serial_ui_lane import DRAIN_TO_DURABLE_HANDOFF, LaneTask
from transfer_seal import SealAttempt, TransferSealError
from warning_presenter import CompletionOutcome, CompletionOutcomeSnapshot


def prepared_completion_contract_steps(
    self,
    prepared_attempt: SealAttempt,
    *,
    existing_event_contract: Optional[Mapping[str, Any]],
    completion_observed_at: datetime.datetime,
    projection_log_path: Path,
    completion_projection_worker: str,
    completion_was_restored: bool,
    master_label: str,
    mutation_identity: Optional[Mapping[str, Any]] = None,
):
    if mutation_identity is not None and not self._mutation_finish_can_apply(
        mutation_identity,
        operation="tray-completion-checkpoint",
    ):
        raise TransferSealError(
            "TRAY_COMPLETE_CONTEXT_STALE",
            "tray completion context changed before durable checkpoint",
        )
    prepared_intent_id = str(prepared_attempt.intent_id or "").strip()
    if existing_event_contract is not None:
        if prepared_intent_id != str(
            existing_event_contract.get("transfer_intent_id") or ""
        ).strip():
            raise TransferSealError(
                "TRAY_COMPLETE_RETRY_INTENT_MISMATCH",
                "저장된 완료 기록과 새 이적 의도가 다릅니다.",
            )
        prepared_contract = dict(existing_event_contract)
    else:
        prepared_contract = self._completion_event_contract(
            observed_at=completion_observed_at,
            projection_log_path=projection_log_path,
            projection_worker_name=completion_projection_worker,
            transfer_attempt=prepared_attempt,
            was_restored_session=completion_was_restored,
            transfer_detail={},
            log_may_have_been_attempted=False,
        )
    self._pending_completion_event_contract = prepared_contract
    if (yield self._current_tray_save_operation()):
        return
    yield from self._completion_outcome_steps(
        CompletionOutcome.RETRY_WAIT,
        item_name=self.current_tray.item_name,
        master_label=master_label,
        scan_count=len(self.current_tray.scanned_barcodes),
        target_count=self.current_tray.tray_size,
        message=(
            "이적 요청은 준비됐지만 완료 복구 계약을 저장하지 못했습니다. "
            "트레이를 잠근 채 프로그램을 종료하지 말고 담당자에게 알리세요."
        ),
        error_code="TRAY_COMPLETE_PREPARED_CONTRACT_PERSIST_FAILED",
    )
    raise TransferSealError(
        "TRAY_COMPLETE_PREPARED_CONTRACT_PERSIST_FAILED",
        "이적 요청 전 완료 복구 계약을 저장하지 못했습니다.",
        retryable=True,
    )


def request_complete_tray(
    self,
    *,
    clock: Any,
    completion_callback: Optional[Callable[[bool], None]] = None,
) -> bool:
    """Submit the GUI completion transport to the shared foreground lane."""

    if self._reject_mutation_during_preflight_hold():
        return False
    if getattr(self.current_tray, "is_test_tray", False):
        completed = bool(self.complete_tray())
        if completion_callback is not None:
            completion_callback(completed)
        return completed
    lane = self._ui_task_lane()
    if lane.is_busy():
        self.show_status_message(
            "이전 중앙 작업 처리 중 · 이번 완료 요청은 접수되지 않았습니다.",
            self.COLOR_DANGER,
            duration=0,
        )
        return False
    blocking_completion = self._active_blocking_completion_snapshot()
    if (
        blocking_completion is not None
        and not blocking_completion.operator_retryable
        and self._operator_review_blocks_mutation()
    ):
        self._render_warning_state()
        return False
    if self._phs_label_exchange_blocks_tray_transition("이적 봉인 및 완료"):
        return False
    if self._transfer_member_exchange_blocks_local_action("이적 봉인 및 완료"):
        return False
    master_label = str(self.current_tray.master_label_code or "")
    master_label_fields = self._parse_new_format_qr(master_label) or {}
    if (
        str(master_label_fields.get("PHS") or "").strip() == "2"
        and len(self.current_tray.scanned_barcodes)
        != int(self.current_tray.tray_size or 0)
    ):
        self.show_status_message(
            "PHS=2 현품표에 등록된 제품을 모두 스캔해야 이적할 수 있습니다.",
            self.COLOR_DANGER,
            duration=0,
        )
        return False
    existing_event_contract = self._active_completion_event_contract()
    try:
        if existing_event_contract is not None:
            completion_observed_at = clock.datetime.fromisoformat(
                str(existing_event_contract["observed_at"])
            )
            completion_was_restored = bool(
                existing_event_contract["was_restored_session"]
            )
            completion_projection_worker = str(
                existing_event_contract["projection_worker_name"]
            )
            projection_log_path = self._completion_projection_log_path(
                str(existing_event_contract["projection_log_name"])
            )
        else:
            completion_observed_at = clock.datetime.now()
            completion_was_restored = bool(self.current_tray.is_restored_session)
            completion_projection_worker = persistent_operator_name(
                self.worker_name
            )
            projection_log_path = self._completion_projection_log_path()
        log_detail = build_tray_complete_detail(
            self.current_tray,
            master_label_fields=master_label_fields,
            end_time=completion_observed_at,
        )
        log_detail["is_restored_session"] = completion_was_restored
        source_label_payload = str(
            getattr(self.current_tray, "active_label_qr_payload", "")
            or master_label
        )
        source_label_fields = self._parse_new_format_qr(source_label_payload)
        if not source_label_fields:
            raise TransferSealError(
                "PHS2_ACTIVE_LABEL_INVALID",
                "현재 사용 현품표를 중앙 이적 원본으로 확인할 수 없습니다.",
            )
        operation_lease_id = str(
            getattr(self.current_tray, "operation_lease_id", "") or ""
        ).strip()
        if (
            str(source_label_fields.get("PHS") or "").strip() == "2"
            and not operation_lease_id
        ):
            raise TransferSealError(
                "OPERATION_LEASE_REQUIRED",
                "이 트레이의 오프라인 이적 확인 정보가 없어 완료할 수 없습니다.",
            )
    except Exception as exc:
        print(f"트레이 완료 lane 준비 실패: {exc.__class__.__name__}")
        self.show_status_message(
            "완료 요청을 안전하게 준비하지 못했습니다. 현재 작업을 보존합니다.",
            self.COLOR_DANGER,
        )
        return False

    identity = self._completion_lane_identity()
    finish_identity = self._capture_mutation_finish_identity()
    coordinator = self._transfer_seal_runtime()
    item_code = str(self.current_tray.item_code or "")
    scanned_barcodes = tuple(log_detail.get("product_barcodes") or ())
    operator = persistent_operator_name(self.worker_name)
    relay_log_path = str(getattr(self, "log_file_path", "") or "")
    existing_contract_snapshot = (
        dict(existing_event_contract)
        if existing_event_contract is not None
        else None
    )

    def work() -> bool:
        attempt = self._prepare_and_attempt_transfer_seal_snapshot(
            coordinator=coordinator,
            source_label_payload=source_label_payload,
            source_label_fields=dict(source_label_fields),
            item_code=item_code,
            operator=operator,
            scanned_barcodes=scanned_barcodes,
            relay_log_file_path=relay_log_path,
            operation_lease_id=operation_lease_id,
            on_prepared=lambda attempt: self._run_durable_ui_steps(
                self._prepared_completion_contract_steps(
                    attempt,
                    existing_event_contract=existing_contract_snapshot,
                    completion_observed_at=completion_observed_at,
                    projection_log_path=projection_log_path,
                    completion_projection_worker=completion_projection_worker,
                    completion_was_restored=completion_was_restored,
                    master_label=master_label,
                    mutation_identity=finish_identity,
                ), lane=lane,
            ),
        )
        precommand_query = None
        if attempt.status == "OPERATOR_REVIEW" and attempt.error_code:
            precommand_query = {
                "master_label": master_label,
                "scanned_barcodes": scanned_barcodes,
                "error_code": attempt.error_code,
            }
        try:
            ui_snapshot = self._work_transfer_coordinator_ui_snapshot(
                master_label=master_label,
                precommand_query=precommand_query,
            )
        except Exception as exc:
            print(
                "완료 UI snapshot 갱신 실패: "
                f"{exc.__class__.__name__}"
            )
            ui_snapshot = {
                "exact_history": True,
                "member": {
                    "known": False,
                    "master_label": master_label,
                    "attempt": None,
                },
                "precommand": None,
            }
        def completion_steps():
            self._apply_transfer_coordinator_ui_snapshot(ui_snapshot)
            if not self._mutation_finish_can_apply(finish_identity, operation="tray-completion"):
                return False
            if self._completion_lane_identity() != identity:
                return False
            return (yield from self._complete_tray_steps(
                _prepared_transfer_attempt=attempt, _lane_prechecked=True,
            ))
        return bool(self._run_durable_ui_steps(completion_steps(), lane=lane))

    completed = False

    def finish(outcome: bool) -> None:
        nonlocal completed
        completed = outcome

    def fail(exc: BaseException) -> None:
        print(f"트레이 완료 lane 실패: {exc.__class__.__name__}")
        self._set_completion_lane_busy(False)
        self.show_status_message(
            "완료 처리를 마치지 못했습니다. 현재 트레이와 복구 계약을 보존합니다.",
            self.COLOR_DANGER,
            duration=0,
        )

    def on_idle() -> None:
        current_generation = int(getattr(self, "_scan_callback_epoch", 0)) == identity[-1]
        if completed and current_generation:
            self._invalidate_pending_scan_callbacks()
        self._set_completion_lane_busy(False)
        if current_generation and completion_callback is not None:
            completion_callback(completed)

    self._set_completion_lane_busy(True)
    admission = lane.submit(
        LaneTask(
            name="tray-completion",
            generation=int(getattr(self, "_scan_callback_epoch", 0) or 0),
            work=work,
            finish=finish, fail=fail,
            on_idle=on_idle,
            shutdown_policy=DRAIN_TO_DURABLE_HANDOFF,
            on_stale=lambda: self._set_completion_lane_busy(False),
        )
    )
    if not admission.accepted:
        self._set_completion_lane_busy(False)
        return False
    self._completion_task_handle = admission.handle
    return True


def complete_tray_steps(
    self,
    *,
    clock: Any,
    session_factory: Callable[[], Any],
    _prepared_transfer_attempt: Optional[SealAttempt] = None,
    _lane_prechecked: bool = False,
):
    if self._reject_mutation_during_preflight_hold():
        return False
    blocking_completion = self._active_blocking_completion_snapshot()
    if (
        blocking_completion is not None
        and not blocking_completion.operator_retryable
        and self._operator_review_blocks_mutation()
    ):
        self._render_warning_state()
        return False
    if self._phs_label_exchange_blocks_tray_transition(
        "이적 봉인 및 완료"
    ):
        return False
    if not _lane_prechecked and self._transfer_member_exchange_blocks_local_action("이적 봉인 및 완료"):
        return False
    master_label_fields = self._parse_new_format_qr(self.current_tray.master_label_code) or {}
    requires_central_ack = str(master_label_fields.get("PHS") or "").strip() == "2"
    if (
        str(master_label_fields.get("PHS") or "").strip() == "2"
        and len(self.current_tray.scanned_barcodes) != int(self.current_tray.tray_size or 0)
    ):
        self.show_status_message(
            "PHS=2 현품표에 등록된 제품을 모두 스캔해야 이적할 수 있습니다. "
            "잔량은 검사 공정에서 이름·시간·품목·수량·수기 코드를 적는 새 양식으로 처리하세요. "
            "RSL1은 업그레이드 전에 시작한 예전 작업 복구에만 사용합니다.",
            self.COLOR_DANGER,
            duration=0,
        )
        return False
    is_test = self.current_tray.is_test_tray
    has_error = self.current_tray.has_error_or_reset
    is_partial = self.current_tray.is_partial_submission
    is_restored = self.current_tray.is_restored_session
    master_label = self.current_tray.master_label_code
    existing_event_contract = self._active_completion_event_contract()
    try:
        if existing_event_contract is not None:
            completion_observed_at = clock.datetime.fromisoformat(
                str(existing_event_contract["observed_at"])
            )
            completion_was_restored = bool(
                existing_event_contract["was_restored_session"]
            )
            completion_projection_worker = str(
                existing_event_contract["projection_worker_name"]
            )
            projection_log_path = self._completion_projection_log_path(
                str(existing_event_contract["projection_log_name"])
            )
        else:
            completion_observed_at = clock.datetime.now()
            completion_was_restored = bool(is_restored)
            completion_projection_worker = persistent_operator_name(
                self.worker_name
            )
            projection_log_path = self._completion_projection_log_path()
    except (KeyError, TypeError, ValueError) as e:
        print(f"트레이 완료 기록 경로 확인 실패: {e}")
        self.show_status_message(
            "트레이 완료 기록 위치를 확인할 수 없어 이적을 시작하지 않습니다.",
            self.COLOR_DANGER,
        )
        return False

    try:
        log_detail = build_tray_complete_detail(
            self.current_tray,
            master_label_fields=master_label_fields,
            end_time=completion_observed_at,
        )
        log_detail["is_restored_session"] = completion_was_restored
    except Exception as e:
        print(f"트레이 완료 기록 생성 실패: {e}")
        self.show_status_message("트레이 완료 기록 생성에 실패했습니다. 작업 상태를 보존합니다.", self.COLOR_DANGER)
        return False

    def persist_prepared_completion_contract(
        prepared_attempt: SealAttempt,
    ) -> None:
        self._persist_prepared_completion_contract(
            prepared_attempt,
            existing_event_contract=existing_event_contract,
            completion_observed_at=completion_observed_at,
            projection_log_path=projection_log_path,
            completion_projection_worker=completion_projection_worker,
            completion_was_restored=completion_was_restored,
            master_label=master_label,
        )

    if is_test:
        test_intent_suffix = self._stable_hash(
            {
                "master_label": master_label,
                "start_time": log_detail.get("start_time"),
                "product_barcodes": log_detail.get("product_barcodes") or [],
                "is_test_tray": True,
            }
        )[:24]
        transfer_attempt = SealAttempt(
            intent_id=f"test-transfer-seal-skipped-{test_intent_suffix}",
            status="TEST_SKIPPED",
        )
    elif _prepared_transfer_attempt is not None:
        transfer_attempt = _prepared_transfer_attempt
    else:
        try:
            transfer_attempt = self._prepare_and_attempt_transfer_seal(
                master_label_fields=master_label_fields,
                log_detail=log_detail,
                on_prepared=persist_prepared_completion_contract,
            )
        except Exception as e:
            print(f"이적 seal 로컬 보존 실패: {e}")
            if (
                self._active_completion_event_contract() is not None
                and self._active_blocking_completion_snapshot() is None
            ):
                yield from self._completion_outcome_steps(
                    CompletionOutcome.RETRY_WAIT,
                    item_name=self.current_tray.item_name,
                    master_label=master_label,
                    scan_count=len(self.current_tray.scanned_barcodes),
                    target_count=self.current_tray.tray_size,
                    message=(
                        "이적 의도는 안전하게 고정했지만 로컬 원장 또는 서버 확인을 "
                        "마치지 못했습니다. 트레이를 잠근 채 같은 요청을 재확인하세요."
                    ),
                    error_code="TRAY_COMPLETE_PREPARED_ATTEMPT_FAILED",
                )
            self.show_status_message(
                "이적 정보를 이 PC에 안전하게 저장하지 못해 작업 상태를 유지합니다.",
                self.COLOR_DANGER,
            )
            return False
    locally_linked = bool(transfer_attempt.local_completion_id)
    post_review_required = bool(
        transfer_attempt.status == "OPERATOR_REVIEW" and locally_linked
    )
    post_review_case: Optional[Dict[str, Any]] = None
    if (
        existing_event_contract is not None
        and str(existing_event_contract.get("transfer_intent_id") or "")
        != str(transfer_attempt.intent_id or "")
    ):
        self._freeze_completion_measurements(completion_observed_at)
        yield from self._completion_outcome_steps(
            CompletionOutcome.OPERATOR_REVIEW,
            item_name=self.current_tray.item_name,
            master_label=master_label,
            scan_count=len(self.current_tray.scanned_barcodes),
            target_count=self.current_tray.tray_size,
            message=(
                "완료 기록 재시도의 이적 의도가 이전 기록과 다릅니다. "
                "트레이를 유지하고 관리자에게 확인하세요."
            ),
            receipt_id=transfer_attempt.receipt_id,
            error_code="TRAY_COMPLETE_RETRY_INTENT_MISMATCH",
        )
        return False
    if transfer_attempt.status == "OPERATOR_REVIEW" and not locally_linked:
        self._freeze_completion_measurements(completion_observed_at)
        safe_message = (
            "서버 확인 미완료 · 현재 트레이와 스캔 목록을 유지합니다.\n"
            "작업을 계속하지 말고 관리자에게 알려 주세요."
        )
        yield from self._completion_outcome_steps(
            CompletionOutcome.OPERATOR_REVIEW,
            item_name=self.current_tray.item_name,
            master_label=master_label,
            scan_count=len(self.current_tray.scanned_barcodes),
            target_count=self.current_tray.tray_size,
            message=safe_message,
            receipt_id=transfer_attempt.receipt_id,
            error_code=transfer_attempt.error_code,
        )
        return False
    if (
        requires_central_ack
        and transfer_attempt.status != "ACKED"
        and not locally_linked
    ):
        if (
            existing_event_contract is not None
            and existing_event_contract.get("log_may_have_been_attempted") is True
        ):
            self._freeze_completion_measurements(completion_observed_at)
            yield from self._completion_outcome_steps(
                CompletionOutcome.OPERATOR_REVIEW,
                item_name=self.current_tray.item_name,
                master_label=master_label,
                scan_count=len(self.current_tray.scanned_barcodes),
                target_count=self.current_tray.tray_size,
                message=(
                    "로컬 완료 기록 이후 중앙 이적 증거가 이전 상태로 돌아갔습니다. "
                    "트레이를 유지하고 관리자에게 확인하세요."
                ),
                receipt_id=transfer_attempt.receipt_id,
                error_code="TRAY_COMPLETE_TRANSFER_EVIDENCE_REGRESSION",
            )
            return False
        self._freeze_completion_measurements(completion_observed_at)
        retry_contract = self._completion_event_contract(
            observed_at=completion_observed_at,
            projection_log_path=projection_log_path,
            projection_worker_name=completion_projection_worker,
            transfer_attempt=transfer_attempt,
            was_restored_session=completion_was_restored,
            transfer_detail=(
                existing_event_contract.get("transfer_detail") or {}
                if existing_event_contract is not None
                else {}
            ),
            log_may_have_been_attempted=False,
        )
        self._pending_completion_event_contract = retry_contract
        yield from self._completion_outcome_steps(
            CompletionOutcome.RETRY_WAIT,
            item_name=self.current_tray.item_name,
            master_label=master_label,
            scan_count=len(self.current_tray.scanned_barcodes),
            target_count=self.current_tray.tray_size,
            message=(
                "중앙 이적 승인 전이므로 트레이·스캔 목록·실물 이동을 잠갔습니다. "
                "네트워크 복구 후 '서버 재확인'을 눌러 같은 이적 요청을 확인하세요."
            ),
            receipt_id=transfer_attempt.receipt_id,
            error_code=transfer_attempt.error_code,
        )
        return False
    self._freeze_completion_measurements(completion_observed_at)
    try:
        log_detail = build_tray_complete_detail(
            self.current_tray,
            master_label_fields=master_label_fields,
            end_time=completion_observed_at,
        )
        log_detail["is_restored_session"] = completion_was_restored
    except Exception as e:
        print(f"고정된 트레이 완료 기록 생성 실패: {e}")
        yield from self._completion_outcome_steps(
            CompletionOutcome.OPERATOR_REVIEW,
            item_name=self.current_tray.item_name,
            master_label=master_label,
            scan_count=len(self.current_tray.scanned_barcodes),
            target_count=self.current_tray.tray_size,
            message="고정된 완료 기록을 다시 만들 수 없습니다. 담당자에게 확인하세요.",
            receipt_id=transfer_attempt.receipt_id,
            error_code="TRAY_COMPLETE_EVENT_REBUILD_FAILED",
        )
        return False
    base_detail_keys = set(log_detail)
    self._attach_transfer_seal_detail(log_detail, transfer_attempt)
    current_transfer_detail = {
        key: value
        for key, value in log_detail.items()
        if key not in base_detail_keys
    }
    stored_transfer_detail = (
        dict(existing_event_contract.get("transfer_detail") or {})
        if existing_event_contract is not None
        else {}
    )
    if stored_transfer_detail:
        legacy_seal_qr_payload = str(
            stored_transfer_detail.pop("seal_qr_payload", "") or ""
        )
        if legacy_seal_qr_payload:
            stored_transfer_detail.setdefault(
                "transfer_seal_qr_sha256",
                hashlib.sha256(
                    legacy_seal_qr_payload.encode("utf-8")
                ).hexdigest(),
            )
        log_detail.update(stored_transfer_detail)
    else:
        stored_transfer_detail = current_transfer_detail
    prior_log_attempt = bool(
        existing_event_contract is not None
        and existing_event_contract.get("log_may_have_been_attempted") is True
    )
    completion_event_contract = self._completion_event_contract(
        observed_at=completion_observed_at,
        projection_log_path=projection_log_path,
        projection_worker_name=completion_projection_worker,
        transfer_attempt=transfer_attempt,
        was_restored_session=completion_was_restored,
        transfer_detail=stored_transfer_detail,
        log_may_have_been_attempted=True,
    )
    log_detail["idempotency_key"] = completion_event_contract["idempotency_key"]
    self._pending_completion_event_contract = completion_event_contract
    if not (yield self._current_tray_save_operation()):
        yield from self._completion_outcome_steps(
            CompletionOutcome.LOCAL_EVENT_RETRY,
            item_name=self.current_tray.item_name,
            master_label=master_label,
            scan_count=len(self.current_tray.scanned_barcodes),
            target_count=self.current_tray.tray_size,
            message=(
                "완료 기록의 재시도 계약을 저장하지 못했습니다. "
                "프로그램을 종료하지 말고 담당자에게 알리세요."
            ),
            receipt_id=transfer_attempt.receipt_id,
            error_code="TRAY_COMPLETE_RETRY_CONTRACT_PERSIST_FAILED",
        )
        return False
    self._last_log_event_was_replay = False
    completion_projection_is_other_worker = (
        persistent_operator_name(completion_projection_worker)
        != persistent_operator_name(self.worker_name)
    )
    completion_log_overrides = (
        {"worker_name_override": completion_projection_worker}
        if completion_projection_is_other_worker
        else {}
    )
    if not (yield lambda: self._log_event(
        'TRAY_COMPLETE',
        detail=log_detail,
        synchronous=True,
        idempotency_key=completion_event_contract["idempotency_key"],
        event_timestamp=completion_event_contract["observed_at"],
        log_file_path_override=str(projection_log_path),
        deduplicate=prior_log_attempt,
        **completion_log_overrides,
    )):
        yield from self._completion_outcome_steps(
            CompletionOutcome.LOCAL_EVENT_RETRY,
            item_name=self.current_tray.item_name,
            master_label=master_label,
            scan_count=len(self.current_tray.scanned_barcodes),
            target_count=self.current_tray.tray_size,
            message=(
                "완료 처리는 확정됐지만 TRAY_COMPLETE 기록을 저장하지 못했습니다. "
                "트레이·스캔 목록을 잠갔습니다. 같은 완료 요청으로 기록 저장을 재시도하세요."
            ),
            receipt_id=transfer_attempt.receipt_id,
            error_code="TRAY_COMPLETE_EVENT_PERSIST_FAILED",
        )
        return False
    completion_event_replayed = bool(
        getattr(self, "_last_log_event_was_replay", False)
    )
    if post_review_required:
        try:
            post_review_case = yield lambda: self._project_transfer_post_review_for_intent(
                transfer_attempt.intent_id
            )
        except Exception:
            # The review case and its projection outbox were committed in
            # the same SQLite transaction as the terminal transfer state.
            # A CSV or receipt failure therefore must not roll back the
            # already durable local completion.
            self._post_review_refresh_required = True

    completion_snapshot: Optional[CompletionOutcomeSnapshot] = None
    if not is_test and (
        transfer_attempt.status == "ACKED" or locally_linked
    ):
        if transfer_attempt.status == "ACKED":
            completion_outcome = CompletionOutcome.ACKED
            completion_message = (
                f"'{self.current_tray.item_name}' 완료 · 서버 이적 확인이 완료되었습니다."
            )
        else:
            completion_outcome = CompletionOutcome.LINKED
            if transfer_attempt.status == "OPERATOR_REVIEW":
                follow_up = "중앙 반영은 담당자 확인이 필요합니다."
            else:
                follow_up = "중앙 반영은 저장된 동일 요청으로 자동 재시도합니다."
            completion_message = (
                f"'{self.current_tray.item_name}' 완료 · {follow_up}"
            )
        completion_snapshot = CompletionOutcomeSnapshot(
            outcome=completion_outcome,
            item_name=self.current_tray.item_name,
            master_label=master_label,
            scan_count=len(self.current_tray.scanned_barcodes),
            target_count=max(len(self.current_tray.scanned_barcodes), self.current_tray.tray_size),
            message=completion_message,
            receipt_id=transfer_attempt.receipt_id,
            error_code=transfer_attempt.error_code,
        )

    self._stop_stopwatch(); self._stop_idle_checker(); self.undo_button['state'] = tk.DISABLED

    completion_summary_requires_reload = (
        completion_event_replayed
        or completion_projection_is_other_worker
    )
    if completion_summary_requires_reload:
        # The durable CSV row may have survived a lost local acknowledgement
        # or process crash. Rebuild counters from the append-only source
        # instead of applying the same completion to memory a second time.
        self._load_session_state()

    if not is_test and not is_partial and self._parse_new_format_qr(master_label):
        self._remember_completed_master_label(master_label)

    item_code = self.current_tray.item_code
    if item_code not in self.work_summary: self.work_summary[item_code] = {'name': self.current_tray.item_name, 'spec': self.current_tray.item_spec, 'count': 0, 'test_count': 0}

    if completion_summary_requires_reload:
        pass
    elif is_test:
        self.work_summary[item_code]['test_count'] += 1
        self.show_status_message(f"테스트 트레이 완료!", self.COLOR_SUCCESS)
    else:
        self.work_summary[item_code]['count'] += 1
        if not is_partial: self.total_tray_count += 1

        # 조건에 맞는 경우 최고 기록 갱신
        if self._completion_time_eligible_for_best_time(log_detail):
            work_time = float(log_detail["work_time_sec"])
            self.completed_tray_times.append(work_time) # 주간 평균 계산을 위해 유지
            try:
                yield lambda: self._update_best_time_records(work_time) # 30일 최고 기록 갱신
            except Exception as e:
                print(f"최고 기록 갱신 실패: {e}")
    state_delete_failed = yield from apply_completed_tray_state_steps(
        self, session_factory=session_factory, _lane_prechecked=_lane_prechecked,
        master_label=master_label, item_code=item_code,
    )
    present_completed_tray(
        self, state_delete_failed=state_delete_failed,
        completion_snapshot=completion_snapshot,
        post_review_required=post_review_required, post_review_case=post_review_case,
    )
    self.tray_last_end_time = clock.datetime.now()
    return True


def apply_completed_tray_state_steps(
    self,
    *,
    session_factory: Callable[[], Any],
    _lane_prechecked: bool,
    master_label: str,
    item_code: str,
):
    """Apply the completed state and finish its durable cleanup before notice."""
    self._pending_completion_event_contract = None
    self.current_tray = session_factory()
    if not _lane_prechecked:
        self._invalidate_pending_scan_callbacks()
    state_delete_failed = (yield self._delete_current_tray_state) is False
    if state_delete_failed:
        yield lambda: self._log_event(
            'TRAY_STATE_DELETE_FAILED_AFTER_COMPLETION',
            detail={
                'master_label_code': master_label,
                'item_code': item_code,
            },
        )
    return state_delete_failed


def present_completed_tray(
    self,
    *,
    state_delete_failed: bool,
    completion_snapshot: Optional[CompletionOutcomeSnapshot],
    post_review_required: bool,
    post_review_case: Optional[Dict[str, Any]],
) -> None:
    """Present the already applied completion using the owner's existing UI."""
    self.scanned_listbox.delete(0, tk.END)
    self._update_all_summaries()
    self._reset_ui_to_waiting_state()
    if state_delete_failed:
        if completion_snapshot is not None:
            self._publish_completion_snapshot(completion_snapshot)
            self._warning_state_presenter().acknowledge()
        self.show_status_message("트레이는 완료되었지만 임시 상태 파일 삭제에 실패했습니다.", self.COLOR_DANGER)
    elif completion_snapshot is not None:
        self._publish_completion_snapshot(completion_snapshot)
    if post_review_required:
        self._present_transfer_post_review_required_notice(
            str((post_review_case or {}).get("review_case_id") or "")
        )

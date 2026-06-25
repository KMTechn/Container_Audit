from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "PRE_PRODUCTION_VALIDATION_MATRIX_20260625.md"
LOCAL_REPORT = ROOT / "docs" / "LOCAL_AUDIT_READINESS_REPORT_20260624.md"
FIELD_RUNBOOK = ROOT / "docs" / "FIELD_UI_HTTPS_CUTOVER_RUNBOOK.md"
WORKFLOW_CHECKLIST = ROOT / "docs" / "WORKFLOW_UIUX_HTTPS_E2E_CHECKLIST.md"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_pre_production_matrix_covers_all_user_requested_p0_p1_p2_gates():
    text = _text(MATRIX)

    required = [
        "승인된 staging/test HTTPS endpoint로 실제 업로드 검증",
        "TLS, proxy headers, certificate chain, HMAC, nonce, idempotency, receipt 저장",
        "실제 작업자 PC/스캐너 UI 시나리오 검증",
        "로그인, 마스터 라벨, 제품 스캔, 자동완료, undo, reset, park/restore, 교체, 개별 교환, 종료/복구",
        "최소 20대 실제/VM PC 동시 전송 검증",
        "같은 파일명, 같은 작업자명, 중복 재전송, 네트워크 끊김, 재시도, 큐 재시작 후 resume",
        "운영과 동일한 DB 스키마/권한에서 ingest 검증",
        "receipt, raw artifact, source_claim, common_ingested_events, projection, summary, quarantine count",
        "다운스트림 화면/프로그램 수신 검증",
        "당일 작업, 과거 조회, trace, summary, export",
        "Syncthing 병행 shadow run 검증",
        "rollback rehearsal",
        "producer credential 운영 검증",
        "시간/clock drift 검증",
        "악성 입력 현장 검증",
        "장애 주입 검증",
        "operator visibility 검증",
        "대용량/장시간 soak test",
        "백업/보존 정책 확인",
        "증거 패킷 scaffold 고정",
        "tools/build_production_evidence_packet.py",
        "production-cutover-packet-v5-20260625",
        "Phase 0-10 approval packet placeholders",
        "release-config-smoke hash",
        "배포 패키지/설정 고정",
        "tools/check_release_config.py",
        "tools/build_release_config.py",
        "config\\parked_trays",
        "운영 대시보드 XSS 렌더링 점검",
        "dashboard_enhanced.js",
        "승인 체크포인트 문서화",
    ]

    assert [item for item in required if item not in text] == []


def test_pre_production_matrix_preserves_external_authority_boundary():
    text = _text(MATRIX)

    required = [
        "Live `C:\\Sync`, production HTTPS endpoint, production DB mutation, scheduled-task apply: BLOCKED until explicit approval.",
        "승인된 staging/test HTTPS endpoint, test DB, physical/VM PC list, rollback window",
        "로컬 자동 검증은 production cutover 승인 증거가 아니다",
        "direct_sync_relay_install_pack.py --apply",
        "scheduled task/service 변경",
        "FQDN HTTPS producer route는 `OPTIONS 200`",
        "실제 POST/HMAC/nonce/idempotency/receipt 저장은 실행되지 않았고",
        "PLAN_C_ROLLOUT_GATE_BLOCKED",
        "approved HTTPS endpoint, credentials, healthy promotion gate, and direct-sync ops schema readiness가 필요하다",
        "OPERATIONAL_DB_READONLY_AUDIT_20260625.md",
        "THREE_AGENT_PRODUCTION_CUTOVER_PLAN_20260625.md",
        "PHASE0_PREFLIGHT_COMMAND_PACKET_20260625.md",
        "PHASE0_EXECUTION_INPUTS_MANIFEST_20260625.md",
        "tools/check_phase0_execution_inputs.py",
        "PHASE0_OWNER_APPROVAL_CHECKLIST_20260625.md",
        "PHASE0_DRY_RUN_TRANSCRIPT_TEMPLATE_20260625.md",
        "PHASE1_ADDITIVE_SCHEMA_APPROVAL_PACKET_20260625.md",
        "PHASE2_POST_SCHEMA_READINESS_PACKET_20260625.md",
        "PHASE3_ONE_PC_CANARY_APPROVAL_PACKET_20260625.md",
        "PHASE4_TWENTY_PC_CONCURRENCY_APPROVAL_PACKET_20260625.md",
        "PHASE5_DOWNSTREAM_RECEIVER_APPROVAL_PACKET_20260625.md",
        "PHASE6_SYNCTHING_SHADOW_APPROVAL_PACKET_20260625.md",
        "PHASE7_ROLLBACK_REHEARSAL_APPROVAL_PACKET_20260625.md",
        "PHASE8_OPERATOR_VISIBILITY_APPROVAL_PACKET_20260625.md",
        "PHASE9_SOAK_SECURITY_APPROVAL_PACKET_20260625.md",
        "PHASE10_FINAL_SIGNOFF_APPROVAL_PACKET_20260625.md",
        "FINAL_LOCAL_CONSISTENCY_AUDIT_20260625.md",
        "production-cutover-packet-v5-20260625",
        "full suite `797 passed`",
        "Phase/packet/readiness gate `98 passed`",
        "loop defect/resource telemetry",
        "DB/app/field/security/downstream/rollback/change-coordinator signoff",
        "DB/app/rollback/downstream/security/change signoff",
        "expected DB SHA-256",
        "backup directory",
        "script hashes",
        "row-count preservation",
        "direct_sync_ops_status.after.json",
        "SQLite `mode=ro` counts",
        "schema-ready zero pre-canary counts",
        "one-PC authenticated canary",
        "HMAC timestamp",
        "nonce",
        "idempotency",
        "receipt summary",
        "source_claim",
        "minimum 20 physical/VM PC concurrency",
        "identity matrix",
        "same Korean filename",
        "same worker name",
        "queue restart/resume",
        "DB reconciliation",
        "operator status",
        "today view",
        "past lookup",
        "export checksum",
        "DB read-only reconciliation",
        "malicious-string rendering",
        "source_claim_history",
        "projection parity",
        "downstream single-count totals",
        "no Syncthing config/folder/service mutation",
        "relay pause/resume",
        "scheduled task/service stop/start",
        "HTTPS failure fallback",
        "CSV/archive/spool/queue preservation",
        "last failure",
        "retry class",
        "next retry",
        "dead-letter/operator-review rows",
        "rollback visibility",
        "producer credential lifecycle",
        "clock drift",
        "malicious SQL/XSS/formula/path traversal corpus",
        "4-8 hour/full-day-volume soak",
        "evidence archive hash",
        "`promotion_allowed=true`",
        "`production_removal_ready=true`",
        "exact Syncthing retirement action",
        "Phase 1 schema apply, canary POST, 20-PC run, shadow run, rollback rehearsal, credential lifecycle, service/task 변경, Syncthing 변경 또는 Syncthing 제거를 승인하지 않는다",
        "phase0_readonly_pass",
        "phase0_blocked_before_mutation",
        "producer POST, schema `--execute`, DB write, credential lifecycle, service/task 변경, relay pause/resume, rollback rehearsal, 20-PC run, Syncthing 변경 또는 Syncthing 제거를 승인하지 않는다",
        "SQLite `mode=ro`/`query_only` counts",
        "exact inputs",
        "OPTIONS-only producer route",
        "Phase 1 handoff inputs",
        "Agent A(Server/DB/Ingest)",
        "Agent B(Producer PC/Field/Security)",
        "Agent C(Downstream/Shadow/Rollback)",
        "legacy dashboard DB로는 healthy",
        "producer_ingest_receipts",
        "producer_ingest_nonces",
        "producer_ingest_raw_artifacts",
        "source_claim_history",
        "transfer_legacy_projection",
        "process_state_summary_sources",
        "common projection `schema_ready=true`와 별개로 direct-sync ops status는 `BLOCKED`",
        "운영 DB 쓰기, schema migration, 실제 producer upload는 DB 백업/rollback window/변경 승인 전까지 금지",
        "Do not remove Syncthing before the P0 evidence pack is complete.",
    ]

    assert [item for item in required if item not in text] == []


def test_pre_production_matrix_has_status_evidence_and_pass_fail_contracts():
    text = _text(MATRIX)

    required = [
        "| Priority | Validation | Current local status | Required pre-prod execution | Evidence to collect | Pass/fail gate |",
        "`LOCAL_AUTOMATED_PASS`",
        "`STAGING_REQUIRED`",
        "`FIELD_REQUIRED`",
        "`PROD_AUTH_REQUIRED`",
        "`READY_TO_RUN`",
        "Evidence to collect",
        "Pass/fail gate",
        "Accepted + quarantined + error rows reconcile to source CSV rows",
        "operational DB read-only audit is `BLOCKED` because required direct-sync tables are missing",
        "no real upload while `producer_ingest_receipts` or `source_claim` tables are missing",
        "Same source event is counted once",
    ]

    assert [item for item in required if item not in text] == []


def test_pre_production_matrix_lists_immediate_local_and_downstream_gates():
    text = _text(MATRIX)

    required = [
        "tests\\test_workflow_https_checklist.py",
        "tests\\test_field_ui_https_cutover_runbook.py",
        "tests\\test_local_audit_readiness_report.py",
        "tests\\test_pre_production_validation_matrix.py",
        "tests\\test_company_server_readonly_precheck_report.py",
        "tests\\test_operational_db_readonly_audit_report.py",
        "tests\\test_operational_change_window_runbook.py",
        "tests\\test_phase0_preflight_command_packet.py",
        "tests\\test_phase0_execution_inputs_manifest.py",
        "tests\\test_phase0_execution_inputs_checker.py",
        "tests\\test_phase0_owner_approval_checklist.py",
        "tests\\test_phase0_dry_run_transcript_template.py",
        "tests\\test_phase1_additive_schema_approval_packet.py",
        "tests\\test_phase2_post_schema_readiness_packet.py",
        "tests\\test_phase3_one_pc_canary_approval_packet.py",
        "tests\\test_phase4_twenty_pc_concurrency_approval_packet.py",
        "tests\\test_phase5_downstream_receiver_approval_packet.py",
        "tests\\test_phase6_syncthing_shadow_approval_packet.py",
        "tests\\test_phase7_rollback_rehearsal_approval_packet.py",
        "tests\\test_phase8_operator_visibility_approval_packet.py",
        "tests\\test_phase9_soak_security_approval_packet.py",
        "tests\\test_phase10_final_signoff_approval_packet.py",
        "tests\\test_three_agent_production_cutover_plan.py",
        "tests\\test_production_evidence_packet.py",
        "tests\\test_final_local_consistency_audit.py",
        "test_virtual_twenty_pc_completion_enqueue_concurrency_preserves_distinct_identities",
        "test_container_audit_tray_complete_twenty_pc_concurrent_projection_and_replay",
        "test_container_audit_direct_ingest_treats_worker_pc_injection_payload_as_data",
        "test_dashboard_received_data_routes_handle_today_past_and_injection_queries",
        "test_worker_pc_injection_payload_is_data_not_query_or_table_mutation",
        "tests\\test_dashboard_static_contract.py",
        "static/dashboard.js",
        "static active-dashboard escaping",
    ]

    assert [item for item in required if item not in text] == []


def test_syncthing_retirement_readiness_requires_all_hard_evidence_gates():
    combined = "\n".join(
        _text(path) for path in [MATRIX, LOCAL_REPORT, FIELD_RUNBOOK, WORKFLOW_CHECKLIST]
    )

    required = [
        "It is not sufficient to remove Syncthing from production",
        "Approved field/test endpoint run with distinct physical PC `source_host_id` values and saved HTTPS receipts",
        "Downstream DB/dashboard proof",
        "Operator report including runtime last failure",
        "Rollback rehearsal",
        "HTTPS 수신 성공, downstream projection 확인, no-double-count 확인 후에만",
        "HTTPS direct ingest must be tested as primary target while Syncthing remains legacy compatibility/archive during migration",
        "Dual-run validation must prove the same source events through Syncthing/archive and HTTPS/API do not double count",
        "Syncthing 제거 가능 only when shadow run no-double-count, 20PC ingest PASS, downstream totals PASS, rollback PASS, operator report PASS",
        "soak/security PASS",
        "backup/retention PASS",
        "release package PASS",
        "dashboard XSS PASS",
        "Syncthing/archive owner signoff",
        "Syncthing retirement gate",
    ]

    assert [item for item in required if item not in combined] == []


def test_syncthing_and_direct_authoritative_claims_are_not_unconditionally_allowed():
    combined = "\n".join(
        _text(path) for path in [MATRIX, LOCAL_REPORT, FIELD_RUNBOOK, WORKFLOW_CHECKLIST]
    ).lower()

    forbidden_unconditional_claims = [
        "production ready",
        "direct_authoritative allowed",
        "syncthing removal approved",
        "remove syncthing now",
        "retire syncthing now",
        "syncthing 제거 승인",
        "syncthing 즉시 제거",
    ]

    assert [claim for claim in forbidden_unconditional_claims if claim in combined] == []

import ast
import re
from pathlib import Path
from types import SimpleNamespace

import Container_Audit as container_module
from Container_Audit import ContainerAudit, ProductExchangeSession, TraySession


ITEM = "AAA2270730100"
MASTER = (
    "PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-COPY-SAFE|"
    f"CLC={ITEM}|LBL=LBL-COPY-SAFE|HSH={'a' * 16}"
)
FORBIDDEN_WORKER_TERMS = (
    "idempotency",
    "receipt",
    "membership",
    "exact resolve",
    "bundle",
    "seal",
    "transfer/package",
    "authority",
    "ledger",
    "registry",
    "writer",
    "http",
    "exception",
    "error_code",
    "status_code",
    "commit",
    "bnd/itg",
    "원장",
)


def _assert_worker_safe(text):
    normalized = str(text or "").casefold()
    for term in FORBIDDEN_WORKER_TERMS:
        assert term.casefold() not in normalized
    assert re.search(r"\bcas\b", normalized, flags=re.IGNORECASE) is None


def test_member_exchange_blocking_dialogs_hide_internal_recovery_terms(monkeypatch):
    dialogs = []
    monkeypatch.setattr(
        container_module.messagebox,
        "showerror",
        lambda title, message, **_kwargs: dialogs.append((title, message)),
    )
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = None
    app._reconcile_pending_local_member_exchanges = lambda: None

    attempts = [
        SimpleNamespace(
            status="OPERATOR_REVIEW",
            local_apply_status="PENDING",
        ),
        SimpleNamespace(
            status="RETRY_WAIT",
            local_apply_status="PENDING",
        ),
    ]
    for attempt in attempts:
        app._current_transfer_member_exchange_attempt = lambda value=attempt: value
        assert app._transfer_member_exchange_blocks_local_action("다음 스캔") is True

    assert len(dialogs) == 2
    for _title, message in dialogs:
        _assert_worker_safe(message)
        assert "다음 스캔" in message
    assert "관리자" in dialogs[0][1]


def test_exact_exchange_policy_dialogs_use_worker_language_only(monkeypatch):
    warnings = []
    monkeypatch.setattr(
        container_module.messagebox,
        "showwarning",
        lambda title, message, **_kwargs: warnings.append((title, message)),
    )
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = ""
    app.log_file_path = ""
    app._exact_transfer_exchange_blocked = lambda: True
    app.transfer_seal_coordinator = SimpleNamespace(
        store=SimpleNamespace(record_exchange_block=lambda **_kwargs: "support-id")
    )

    assert app._block_unsafe_exact_exchange() is True
    assert app._block_unsafe_exact_master_label_replacement() is True

    assert len(warnings) == 2
    for _title, message in warnings:
        _assert_worker_safe(message)
        assert "관리자" in message


def _central_exchange_app(attempt):
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = "tester"
    app.current_tray = TraySession(
        master_label_code=MASTER,
        item_code=ITEM,
    )
    app.current_exchange_session = ProductExchangeSession(
        item_code=ITEM,
        item_name="테스트 품목",
        target_quantity=1,
        defective_barcodes=[f"{ITEM}-OLD-1"],
        good_barcodes=[f"{ITEM}-NEW-1"],
        current_step="scan_good",
    )
    app.exchange_complete_button = SimpleNamespace(config=lambda **_kwargs: None)
    app._active_transfer_exchange_mode = True
    coordinator = SimpleNamespace(
        prepare=lambda **_kwargs: SimpleNamespace(intent_id="intent-support-only"),
        attempt=lambda _intent_id: attempt,
    )
    app._transfer_member_exchange_runtime = lambda: coordinator
    return app, coordinator


def test_central_exchange_failure_keeps_raw_diagnostics_out_of_worker_dialog(
    monkeypatch,
):
    attempt = SimpleNamespace(
        status="OPERATOR_REVIEW",
        error_code="HTTP_409_BUNDLE_CAS_CONFLICT",
        error_message=(
            "HTTP 409 authority ledger registry writer-claim "
            "bundle-id=secret-bundle seal-id=secret-seal receipt=secret-receipt"
        ),
    )
    app, _coordinator = _central_exchange_app(attempt)
    dialogs = []
    monkeypatch.setattr(
        container_module.messagebox,
        "showerror",
        lambda title, message, **_kwargs: dialogs.append((title, message)),
    )

    app._complete_exchange()

    assert len(dialogs) == 1
    _title, worker_copy = dialogs[0]
    _assert_worker_safe(worker_copy)
    assert "관리자" in worker_copy
    assert "secret-bundle" not in worker_copy
    assert "secret-seal" not in worker_copy
    assert "secret-receipt" not in worker_copy
    assert attempt.error_code == "HTTP_409_BUNDLE_CAS_CONFLICT"
    assert "secret-bundle" in attempt.error_message


def test_central_exchange_prepare_exception_is_not_copied_to_worker_dialog(
    monkeypatch,
):
    app, coordinator = _central_exchange_app(SimpleNamespace(status="ACKED"))

    def fail_prepare(**_kwargs):
        raise ValueError(
            "HTTP 412 AUTHORITY_INVALID bundle-id=secret-bundle status_code=412"
        )

    coordinator.prepare = fail_prepare
    dialogs = []
    monkeypatch.setattr(
        container_module.messagebox,
        "showerror",
        lambda title, message, **_kwargs: dialogs.append((title, message)),
    )

    app._complete_exchange()

    assert len(dialogs) == 1
    _title, worker_copy = dialogs[0]
    _assert_worker_safe(worker_copy)
    assert "secret-bundle" not in worker_copy


def test_worker_ui_literals_and_direct_diagnostics_exclude_internal_terms():
    source_path = Path(container_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    ui_methods = {
        "showerror",
        "showwarning",
        "showinfo",
        "show_status_message",
        "show_fullscreen_warning",
    }
    literal_violations = []
    diagnostic_violations = []

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.function_name = ""

        def visit_FunctionDef(self, node):
            previous = self.function_name
            self.function_name = node.name
            self.generic_visit(node)
            self.function_name = previous

        def visit_Call(self, node):
            method = getattr(node.func, "attr", "")
            if method not in ui_methods:
                self.generic_visit(node)
                return
            segment = ast.get_source_segment(source, node) or ""
            lowered = segment.casefold()
            for term in FORBIDDEN_WORKER_TERMS:
                if term.casefold() in lowered:
                    literal_violations.append((node.lineno, term))
            if re.search(r"\bcas\b", lowered, flags=re.IGNORECASE):
                literal_violations.append((node.lineno, "CAS"))
            if self.function_name not in {"_register_worker_name", "start_work"}:
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and (
                        child.id in {"e", "exc", "error", "quarantine_error"}
                    ):
                        diagnostic_violations.append((node.lineno, child.id))
                    if (
                        isinstance(child, ast.Attribute)
                        and isinstance(child.value, ast.Name)
                        and child.value.id == "attempt"
                        and child.attr in {"error_code", "error_message", "status_code"}
                    ):
                        diagnostic_violations.append((node.lineno, child.attr))
            self.generic_visit(node)

    Visitor().visit(tree)

    assert literal_violations == []
    assert diagnostic_violations == []

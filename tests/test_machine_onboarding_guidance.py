"""Exercise the actual GUI handler with a headless message sink."""
import ast
from pathlib import Path
from types import SimpleNamespace
import pytest


def test_install_server_change_uses_existing_refusal_guidance():
    tree = ast.parse((Path(__file__).resolve().parents[1] / "Container_Audit.py").read_text(encoding="utf-8-sig"))
    nodes = [node for node in tree.body if
             isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "MACHINE_ONBOARDING_ERROR_MESSAGES" for target in node.targets)
             or isinstance(node, ast.FunctionDef) and node.name == "_show_first_run_onboarding_error"]
    messages, observations = [], []
    namespace = {
        "CurrentUserOnboardingError": Exception, "DataGenerationBlocked": RuntimeError,
        "FIRST_RUN_ONBOARDING_ERROR_MESSAGE": "default", "FIRST_RUN_ONBOARDING_ERROR_TITLE": "title",
        "messagebox": SimpleNamespace(showerror=lambda title, message: messages.append(message)),
        "_startup_refusal": lambda *_args, **_kwargs: False,
        "_startup_check_observe": lambda *args, **kwargs: observations.append((args, kwargs)),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "owned-guidance", "exec"), namespace)
    failure = SimpleNamespace(status="RECOVERY_REQUIRED", report_path=Path("owned-report.json"), __cause__=None)
    namespace["_show_first_run_onboarding_error"](failure)
    assert messages == ['회사 서버 주소가 설치 때와 다릅니다.\n현장 관리자에게 알리세요.']
    assert observations == [(("finish", "FIRST_RUN_SETUP_REQUIRED"), {"refused": True})]

@pytest.mark.parametrize("status,expected", [
    ("PENDING_WORKER_SID_MISMATCH", "지정된 작업자 계정"),
    ("MACHINE_ONBOARDING_FAILED", "설치 복구"),
])
def test_pending_reason_reaches_field_guidance(status, expected):
    tree = ast.parse((Path(__file__).resolve().parents[1] / "Container_Audit.py").read_text(encoding="utf-8-sig"))
    nodes = [node for node in tree.body if
        isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "MACHINE_ONBOARDING_ERROR_MESSAGES" for target in node.targets)
        or isinstance(node, ast.FunctionDef) and node.name == "_show_first_run_onboarding_error"]
    assert len(nodes) == 2
    messages = []
    namespace = {"CurrentUserOnboardingError": Exception, "DataGenerationBlocked": RuntimeError,
        "FIRST_RUN_ONBOARDING_ERROR_MESSAGE": "default", "FIRST_RUN_ONBOARDING_ERROR_TITLE": "title",
        "messagebox": SimpleNamespace(showerror=lambda title, message: messages.append(message)),
        # Startup refusal not recorded/acknowledged: the field guidance dialog is the operator path.
        "_startup_refusal": lambda reason, **kwargs: False}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "owned-guidance", "exec"), namespace)
    failure = SimpleNamespace(status=status, report_path=Path("owned-report.json"), __cause__=None)
    namespace["_show_first_run_onboarding_error"](failure)
    assert len(messages) == 1 and expected in messages[0]
    assert "default" not in messages[0]

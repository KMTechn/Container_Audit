"""Retry the same official completed recovery after it removed its own fence."""
import json
import pytest

from tests.powershell_contracts import run_functions
from tests.test_machine_install_completed_recovery import DRIVER, FUNCTIONS, INSTALLER
from tests.test_machine_compensation_completed_recovery import COMPENSATED_DRIVER, COMPENSATED_FUNCTIONS
from tests.test_machine_actual_compensation_completed_recovery import ACTUAL_COMPENSATED_DRIVER
from tests.test_machine_operation_completed_recovery import (
    RESULT_DRIVER, SETUP_STAGE, RUN_STAGE, SUMMARY_FILE,
)


@pytest.mark.parametrize("engine", ["powershell", "pwsh"])
@pytest.mark.parametrize("kind", [
    "INSTALL", "UNINSTALL", "RESTORE_VERIFIED_REPLACEMENT",
    "INSTALL_COMPENSATED", "UNINSTALL_COMPENSATED",
])
def test_completed_recovery_retry_keeps_the_same_result(tmp_path, engine, kind):
    values = {"CA_COMPLETED_STAGE": SETUP_STAGE, "CA_COMPLETED_CASE": "completed"}
    functions = FUNCTIONS
    if kind.endswith("_COMPENSATED"):
        driver = ACTUAL_COMPENSATED_DRIVER if kind == "INSTALL_COMPENSATED" else COMPENSATED_DRIVER
        functions = COMPENSATED_FUNCTIONS
        values["CA_COMPLETED_OPERATION"] = kind.removesuffix("_COMPENSATED")
    elif kind == "INSTALL":
        driver = DRIVER
    else:
        driver = RESULT_DRIVER
        values["CA_RESULT_OPERATION"] = kind
    result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
    assert result.returncode == 0, "retry fixture setup failed"
    summaries = []
    for _ in range(2):
        values["CA_COMPLETED_STAGE"] = RUN_STAGE
        result = run_functions(tmp_path, INSTALLER, functions, driver, values=values, engine=engine)
        assert result.returncode == 0, "retry driver failed"
        summary = json.loads((tmp_path / SUMMARY_FILE).read_text(encoding="utf-8"))
        assert summary["code"] == "", "the same completed recovery must be idempotent"
        assert not summary["fence_present"]
        assert summary["audit_preserved"] and summary["code_preserved"] and summary["audit_spaced"]
        assert summary["restored"] == summary["audit_writes"] == 0
        assert summary["release_receipts"] == 1
        summaries.append(summary)
    assert summaries[0]["public_code"] == summaries[1]["public_code"] == "PASS_MACHINE_RECOVERED"

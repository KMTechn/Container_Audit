import json
from pathlib import Path

import pytest
import writer_session_fence as fence
from tests.powershell_contracts import run_functions
from tests.test_general_completed_release_recovery import DRIVER, FUNCTIONS, INSTALLER


ENGINES = ["powershell.exe", "pwsh.exe"]
STAMPS = ["2026-10-21T00:00:00.1234500Z", "2026-10-21T00:00:00.0000000Z"]


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("stamp", STAMPS)
@pytest.mark.parametrize("private", [False, True], ids=["public", "private"])
def test_audit_time_fields_keep_ps51_wire_bytes(tmp_path, engine, stamp, private):
    payload = {
        "status": "RESTORE_AWAITING_FENCE_RELEASE",
        "session_started_at_utc": stamp,
        "owner_started_at_utc": stamp,
        "helper_started_at_utc": stamp,
        "completed_fence_release": {"fence": {"session_started_at_utc": stamp}},
        "machine_fence": {"session_started_at_utc": stamp},
        "events": [{"created_at_utc": stamp}],
    }
    wire = json.dumps(payload, separators=(",", ":")) + "\n"
    script = r'''
$payload=$env:CA_AUDIT_TIMESTAMP_WIRE|ConvertFrom-ContainerWriterFenceJson
$json=ConvertTo-CanonicalAuditJson $payload -PrivateDiagnostics:($env:CA_AUDIT_TIMESTAMP_PRIVATE -ceq 'yes')
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'audit-wire.json'),$json,[Text.UTF8Encoding]::new($false))
'''
    result = run_functions(
        tmp_path, INSTALLER, ["ConvertTo-CanonicalAuditJson"], script,
        values={"CA_AUDIT_TIMESTAMP_WIRE": wire,
                "CA_AUDIT_TIMESTAMP_PRIVATE": "yes" if private else "no"}, engine=engine,
    )
    assert result.returncode == 0
    # This exact, ordered, compact UTF-8 envelope is the original PS5.1 output.
    assert (tmp_path / "audit-wire.json").read_bytes() == wire.encode("utf-8")


def _actual_audit_driver(stamp):
    direct_save = "[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 40)+[char]10,[Text.UTF8Encoding]::new($false))"
    actual_save = r'''$encoded=if($Value -is [Collections.IDictionary] -and $Value.Contains('completed_fence_release')){ConvertTo-CanonicalAuditJson $Value}else{($Value|ConvertTo-Json -Depth 40)+[char]10}
    [IO.File]::WriteAllText($Path,$encoded,[Text.UTF8Encoding]::new($false))'''
    original_clock = "$canonicalWriterFenceStartedAtUtc=[DateTime]::UtcNow.ToString('o')"
    assert DRIVER.count(direct_save) == DRIVER.count(original_clock) == 1
    return DRIVER.replace(direct_save, actual_save).replace(
        original_clock, "$canonicalWriterFenceStartedAtUtc='" + stamp + "'"
    )


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("stamp", STAMPS)
def test_actual_audit_public_recovery_releases_ledger_admission(tmp_path, engine, stamp):
    driver = _actual_audit_driver(stamp)
    values = {"CA_GENERAL_BOUNDARY": "A_AFTER_SET", "CA_GENERAL_STAGE": "setup"}
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver, values=values, engine=engine)
    assert result.returncode == 73
    values["CA_GENERAL_STAGE"] = "observe"
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver, values=values, engine=engine)
    assert result.returncode == 0
    observed = json.loads((tmp_path / "general-observed.json").read_text(encoding="utf-8-sig"))
    assert all(observed["refusals"].values())
    control = Path(observed["control_root"])
    environment = {"CONTAINER_AUDIT_DATA_ROOT": observed["data_root"]}
    with pytest.raises(fence.WriterFencedError) as blocked:
        with fence._writer_admission("ledger_storage", control_root=control, environ=environment):
            pytest.fail("ledger admission crossed the waiting fence")
    assert blocked.value.code == "ACTIVE_WRITER_FENCE"
    context = json.loads((tmp_path / "boundary-context.json").read_text(encoding="utf-8-sig"))
    audit_path = Path(context["audit_path"])
    before = audit_path.read_bytes()
    audit = json.loads(before)
    assert audit["status"] == "RESTORE_AWAITING_FENCE_RELEASE"
    proof = audit["completed_fence_release"]
    prepared = json.loads(Path(proof["fence"]["prepared_receipt_path"]).read_bytes())
    assert proof["fence"]["session_started_at_utc"] == prepared["session_started_at_utc"] == stamp
    # Exercise the original public If branch directly, before any internal recovery.
    values["CA_GENERAL_STAGE"] = "public"
    result = run_functions(tmp_path, INSTALLER, FUNCTIONS, driver, values=values, engine=engine)
    assert result.returncode == 0
    assert audit_path.read_bytes() == before
    with fence._writer_admission("ledger_storage", control_root=control, environ=environment):
        pass

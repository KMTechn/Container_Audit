"""Public recovery notices from actual machine fence denial boundaries."""
import json
from pathlib import Path
import uuid

import pytest

import writer_session_fence as fence
from tests.powershell_contracts import run_functions
from tests.test_writer_session_fence import _active_payload, _write_active

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "CONTAINER_AUDIT_MACHINE_RECOVERY="


def _machine_fence(tmp_path, *, machine=True, owner="canonical_installer"):
    private = uuid.uuid4().hex
    state = tmp_path / private / ("machine-install" if machine else "other-install")
    root = state / "control" / "writer-session"
    payload = _active_payload()
    payload["owner_kind"] = owner
    run = payload["replacement_transaction_id"]
    receipt = state / "install-audit" / f"canonical-portable-{run}.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("{}\n", encoding="utf-8")
    payload["prepared_receipt_path"] = str(receipt.resolve())
    import hashlib
    payload["prepared_receipt_sha256"] = hashlib.sha256(receipt.read_bytes()).hexdigest()
    active = _write_active(root, payload)
    return root, payload, active, private


def _notice(output, payload, private):
    lines = [line for line in output.splitlines() if line.startswith(PREFIX)]
    assert len(lines) == 1
    public = json.loads(lines[0][len(PREFIX):])
    audit = rf"install-audit\canonical-portable-{payload['replacement_transaction_id']}.json"
    assert public == {"guidance": f"Recovery: -RecoverMachineInstallation; audit: {audit}"}
    for field in ("session_id", "attempt_id", "session_authority_mutex_name", "prepared_receipt_path",
                  "prepared_receipt_sha256", "delegation_sha256", "orchestrator_sha256"):
        value = payload[field]
        if value:
            assert value not in output
    assert private not in output
    assert "S-1-" not in output


@pytest.mark.parametrize("nested", (False, True))
def test_active_writer_fence_notice_is_public_and_read_only(tmp_path, monkeypatch, capsys, nested):
    root, payload, active, private = _machine_fence(tmp_path)
    before = active.read_bytes(), active.stat().st_mtime_ns
    if nested:
        monkeypatch.setattr(fence._WRITER_LOCAL, "depth", 1, raising=False)
        monkeypatch.setattr(fence._WRITER_LOCAL, "active", fence.active_fence(root), raising=False)
        monkeypatch.setattr(fence._WRITER_LOCAL, "environ", {}, raising=False)
        monkeypatch.setattr(fence._WRITER_LOCAL, "root", root, raising=False)
    with pytest.raises(fence.WriterFencedError) as denied:
        with fence.writer_admission("current_user_onboarding", control_root=root, environ={}):
            pytest.fail("fenced writer was admitted")
    assert denied.value.code == "ACTIVE_WRITER_FENCE"
    output = capsys.readouterr()
    _notice(output.out + output.err, payload, private)
    assert (active.read_bytes(), active.stat().st_mtime_ns) == before


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("operation", ("install", "kit_rollback"))
def test_already_active_notice_survives_canonical_or_kit_denial(tmp_path, engine, operation):
    root, payload, active, private = _machine_fence(tmp_path)
    before = active.read_bytes(), active.stat().st_mtime_ns
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", ["Write-CanonicalMachinePublicRecord", "Get-CanonicalMachineFailureReason", "Get-CanonicalMachineHelperReason"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
try {
    [void](Start-ContainerWriterFence -ControlRoot $env:CA_GUIDANCE_CONTROL -Status 'INSTALLING' -OwnerKind 'canonical_installer')
    throw 'Fence was unexpectedly acquired.'
} catch {
    if($_.Exception.Message -cne 'CONTAINER_WRITER_FENCE_ALREADY_ACTIVE'){throw}
    Write-CanonicalMachinePublicRecord 'MACHINE_INSTALL_FAILED'
}
''', engine=engine, values={"CA_GUIDANCE_CONTROL": str(root)}) if operation == "install" else run_functions(
        tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1", ["Write-CanonicalMachinePublicRecord", "Get-CanonicalMachineFailureReason", "Get-CanonicalMachineHelperReason"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
try {
    [void](Start-ContainerWriterFence -ControlRoot $env:CA_GUIDANCE_CONTROL -Status 'INSTALLING' -OwnerKind 'canonical_installer')
    throw 'Fence was unexpectedly acquired.'
} catch {
    if($_.Exception.Message -cne 'CONTAINER_WRITER_FENCE_ALREADY_ACTIVE'){throw}
    'KIT_BLOCKED_ALREADY_ACTIVE'
}
''', engine=engine, values={"CA_GUIDANCE_CONTROL": str(root)})
    assert result.returncode == 0, result.stdout + result.stderr
    _notice(result.stdout + result.stderr, payload, private)
    assert (active.read_bytes(), active.stat().st_mtime_ns) == before


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("code", ("MACHINE_RECOVERY_CHILD_ACTIVE", "MACHINE_RECOVERY_CHILD_UNRECORDED",
                                 "MACHINE_RECOVERY_CHILD_IDENTITY_INVALID", "MACHINE_RECOVERY_CHILD_EXIT_UNPROVEN"))
def test_only_live_child_guidance_requests_retry(tmp_path, engine, code):
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1",
                           ["Write-CanonicalMachinePublicRecord"],
                           "Write-CanonicalMachinePublicRecord $env:CA_GUIDANCE_CODE",
                           engine=engine, values={"CA_GUIDANCE_CODE": code})
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    public = json.loads(lines[0].split("=", 1)[1])
    expected = ("설치가 아직 진행 중입니다 — 끝난 뒤 같은 명령을 다시 실행하세요"
                if code == "MACHINE_RECOVERY_CHILD_ACTIVE" else
                "설치 자식의 종료를 확인하지 못했습니다. 자료와 설치 기록을 보존하고 관리자 지원 복구를 요청하세요.")
    assert public["code"] == code
    assert public["guidance"] == expected
    assert "S-1-" not in result.stdout + result.stderr


@pytest.mark.parametrize("machine,owner", ((False, "canonical_installer"), (True, "session_adapter")))
def test_other_fences_do_not_advertise_machine_recovery(tmp_path, capsys, machine, owner):
    root, _, _, _ = _machine_fence(tmp_path, machine=machine, owner=owner)
    with pytest.raises(fence.WriterFencedError):
        with fence.writer_admission("current_user_onboarding", control_root=root, environ={}):
            pytest.fail("fenced writer was admitted")
    output = capsys.readouterr()
    assert PREFIX not in output.out + output.err


@pytest.mark.parametrize("engine", ("powershell.exe", "pwsh.exe"))
@pytest.mark.parametrize("machine,owner", ((False, "canonical_installer"), (True, "session_adapter")))
def test_other_powershell_fences_keep_original_denial(tmp_path, engine, machine, owner):
    root, _, active, _ = _machine_fence(tmp_path, machine=machine, owner=owner)
    before = active.read_bytes(), active.stat().st_mtime_ns
    result = run_functions(tmp_path, ROOT / "INSTALL_CANONICAL_PORTABLE.ps1",
                           ["Write-CanonicalMachinePublicRecord"], r'''
. (Join-Path (Split-Path -Parent $env:CA_CONTRACT_SOURCE) 'tools/container_writer_fence.ps1')
try {
    [void](Start-ContainerWriterFence -ControlRoot $env:CA_GUIDANCE_CONTROL -Status 'INSTALLING' -OwnerKind 'canonical_installer')
    throw 'Fence was unexpectedly acquired.'
} catch {
    if($_.Exception.Message -cne 'CONTAINER_WRITER_FENCE_ALREADY_ACTIVE'){throw}
}
''', engine=engine, values={"CA_GUIDANCE_CONTROL": str(root)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert PREFIX not in result.stdout + result.stderr
    assert (active.read_bytes(), active.stat().st_mtime_ns) == before

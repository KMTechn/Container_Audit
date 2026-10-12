"""FG-01: exercise daily A-to-B apply, then the real removal admission."""
from contextlib import nullcontext
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from tests.test_support_packet_removal import (
    _packet_bytes, _record_installed_packet, support_removal_packets,
)
from tests.test_portable_data_generation import signed_packet, signed_proof


@pytest.fixture
def updated_packets(tmp_path, monkeypatch, support_removal_packets):
    import auto_update as update
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    from tests.test_auto_update import OLD, NEW, LATER
    from tests.test_signed_pairrule import signed

    seed = support_removal_packets
    managed = tmp_path / "m"
    fixed = managed / "current"
    old = managed / "versions" / OLD
    active = managed / "versions" / NEW
    candidate = tmp_path / "candidate"
    old_support = tmp_path / "support-a"
    for target, version, build in (
        (fixed, "v2.0.99", OLD), (seed.support, "v2.0.100", NEW),
        (candidate, "v2.0.101", "c" * 40),
    ):
        if target != seed.support:
            shutil.copytree(seed.installed, target,
                            ignore=shutil.ignore_patterns("bootstrap-integrity.json"))
        path = target / "portable-manifest.json"
        metadata = json.loads(path.read_bytes())
        for name in ("data_generation_signed_manifest", "data_generation_signature_hex"):
            metadata.pop(name, None)
        metadata.update(version=version, source_commit=build, startup_update_protocol=1,
                        contract_sha256=("d" if build == OLD else "e") * 64,
                        data_api_contract_sha256="f" * 64,
                        writer_sink_inventory_contract_sha256="f" * 64)
        path.write_text(json.dumps(metadata), encoding="utf-8")
        (target / "app/Container_Audit.py").write_text(
            f'CURRENT_VERSION = "{version}"\n', encoding="utf-8")
    _record_installed_packet(tmp_path, fixed)
    shutil.copytree(fixed, old)
    shutil.copytree(fixed, old_support,
                    ignore=shutil.ignore_patterns("bootstrap-integrity.json"))
    _record_installed_packet(tmp_path, seed.support)
    # Only the installed/extracted versions carry the installer-owned record.
    candidate_record = seed.support / "bootstrap-integrity.json"
    control = managed / "update-control"
    stage = tmp_path / "stage"
    control.mkdir()
    stage.mkdir()
    update.write_json_durable(control / "policy.json", {
        "schema": "container-audit-startup-update-policy-v1",
        "operator_sid": seed.subject, "operator_local_app_data": str(tmp_path / "operator"),
        "staging_root": str(stage), "channel": "stable",
        "feed_url": "/".join(("https:", "", "example.invalid", "feed")),
    })
    update.write_json_durable(control / 'active.json', {'schema': update.SCHEMA, 'sha': OLD, 'transition_id': 'CANONICAL_INSTALL'})
    update.write_json_durable(control / 'transition.json', {
        'schema': update.SCHEMA, 'phase': 'DEFERRED',
        'deferred_at': '2026-10-12T00:00:00Z', 'reason': 'canonical installation',
        'failed_shas': [],
    })
    update.write_json_durable(stage / "prepared.json", {"source_commit": NEW})
    for name in ("manifest.json", "manifest.sig", "packet.zip"):
        (stage / name).write_bytes(b"isolated archive adapter input")

    def installed_proof(_control, mode, *, code_root=None):
        if mode == "Verify":
            detail = onboarding.verify_bootstrap_integrity(SimpleNamespace(
                app_root=code_root, bootstrap_integrity_path=code_root / "bootstrap-integrity.json",
            ), required=True, expected_entrypoint="app/Container_Audit.py")
            assert detail["status"] == "PASS"
        return ""

    def manifest(bundle, **_kwargs):
        return update.read_json(bundle / "portable-manifest.json")

    def extract(_packet, output, _policy):
        shutil.copytree(seed.support, output / "Container_Audit")

    def processes(_control):
        state = update.optional_record(control / "transition.json")
        if (not state or state["phase"] == "PREPARED") or (state.get("phase") == "DEFERRED" and not state.get("candidate_sha")):
            return []
        assert state["phase"] == "APPLIED_PENDING_READY"
        update.write_json_durable(stage / "trial.json", {
            "nonce": state["nonce"], "transition_id": state["transition_id"], "pid": 42,
        })
        update.write_json_durable(stage / "ready.json", {
            **{check: True for check in update.READY_CHECKS},
            "nonce": state["nonce"], "transition_id": state["transition_id"],
            "sha": NEW, "pid": 42, "ready_at": LATER,
        })
        return [dict(pid=pid, observable=True, sha=NEW, sid=seed.subject,
                     role=role, ordinary_user=True, created_at=LATER)
                for pid, role in ((42, "gui"), (43, "relay"))]

    monkeypatch.setattr(update, "update_lock", lambda *_a, **_k: nullcontext())
    monkeypatch.setattr(update, "fixed_helper", installed_proof)
    monkeypatch.setattr(update, "version_manifest", manifest)
    monkeypatch.setattr(update, "verify_prepared_packet", lambda *_a, **_k: (
        {**signed(manifest(old), manifest(seed.support)), "source_commit": NEW},
        {"archive_policy": {}, "sha256": "3" * 64},
    ))
    monkeypatch.setattr(update, "copy_prepared_file", lambda source, target, **_k:
                        target.write_bytes(source.read_bytes()))
    monkeypatch.setattr(update, "extract_prepared_code", extract)
    monkeypatch.setattr(update, "process_snapshot", processes)
    monkeypatch.setattr(update, "now_utc", lambda: LATER)
    assert update.apply_prepared(control) == 0
    assert update.read_json(control / "active.json")["sha"] == NEW
    assert update.read_json(control / "transition.json")["phase"] == "CONFIRMED"
    assert update.read_json(fixed / "portable-manifest.json")["source_commit"] == OLD
    candidate_record.unlink()
    monkeypatch.setattr(guard, "__file__", str(active / "app/data_generation_guard.py"))
    guard.record_before_data_open(seed.paths.data_root)
    markers = guard.marker_paths(seed.paths.data_root, seed.subject)
    assert all(json.loads(path.read_bytes())["data_compatible_min_version"] == "v2.0.100" for path in markers)

    def remove(packet=seed.support):
        monkeypatch.setattr(guard, "__file__", str(packet / "app/data_generation_guard.py"))
        return onboarding.remove_current_user_setup(
            fixed / "app", environ=seed.environment,
            autostart_remover=lambda: seed.observed.append("autostart") or {"status": "ABSENT"},
            relay_stopper=lambda _root: seed.observed.append("relay") or {"status": "ABSENT"},
        )

    return SimpleNamespace(root=managed, fixed=fixed, active=active, support=seed.support,
                           old_support=old_support, candidate=candidate, control=control,
                           markers=markers, seed=seed, remove=remove)


def test_b_support_packet_removes_after_daily_update(updated_packets):
    packets = updated_packets
    before = [_packet_bytes(root) for root in (packets.root, packets.support)]
    markers = [path.read_bytes() for path in packets.markers]
    event = packets.seed.event.read_bytes()
    assert packets.remove()["status"] == "PASS_DATA_PRESERVED"
    assert packets.seed.observed == ["autostart", "relay"]
    assert [path.read_bytes() for path in packets.markers] == markers
    assert packets.seed.event.read_bytes() == event
    assert [_packet_bytes(root) for root in (packets.root, packets.support)] == before


def test_a_support_packet_cannot_remove_b_generation(updated_packets):
    import current_user_onboarding as onboarding

    packets = updated_packets
    before = [_packet_bytes(root) for root in (packets.root, packets.old_support)]
    with pytest.raises(onboarding.CurrentUserOnboardingError) as caught:
        packets.remove(packets.old_support)
    assert caught.value.__cause__.decision["status"] == "UNKNOWN"
    assert packets.seed.observed == []
    assert not packets.seed.paths.removal_report_path.exists()
    assert [_packet_bytes(root) for root in (packets.root, packets.old_support)] == before


def test_fixed_a_host_still_refuses_b_data(updated_packets):
    import current_user_onboarding as onboarding

    packets = updated_packets
    with pytest.raises(onboarding.CurrentUserOnboardingError) as caught:
        packets.remove(packets.fixed)
    assert caught.value.__cause__.decision["status"] == "REFUSE"
    assert packets.seed.observed == []
    assert not packets.seed.paths.removal_report_path.exists()


@pytest.mark.parametrize("installed_host", [False, True])
def test_updated_inventory_proof_stays_outside_writer_admission(updated_packets, monkeypatch, installed_host):
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    import writer_session_fence as fence

    depths = []
    original = onboarding._file_sha256

    def observe(*args, **kwargs):
        depths.append(getattr(fence._WRITER_LOCAL, "depth", 0))
        return original(*args, **kwargs)

    monkeypatch.setattr(onboarding, "_file_sha256", observe)
    monkeypatch.setattr(guard, "_PORTABLE_RELEASE_CACHE", {})
    packets = updated_packets
    assert packets.remove(packets.active if installed_host else packets.support)["status"] == "PASS_DATA_PRESERVED"
    assert depths and set(depths) == {0}


@pytest.mark.parametrize("engine", ["powershell.exe", "pwsh.exe"])
def test_worker_reinstall_removes_with_verified_active_host(tmp_path, updated_packets, engine):
    from tests.powershell_contracts import run_functions

    packets = updated_packets
    source = Path(__file__).resolve().parents[1] / "INSTALL_CANONICAL_PORTABLE.ps1"
    result = run_functions(tmp_path, source, ["Product"], r"""
$placement=@($ast.FindAll({param($n)
 $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text -ceq '$placement -eq ''INSTALL_REQUIRED'''
},$true))
if($placement.Count -ne 1){throw 'placement branch missing'}
$remove=@($placement[0].FindAll({param($n)
 $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text -ceq '$supportedPlacement' -and
 $n.Extent.Text.Contains('--remove-current-user-setup')
},$true))
if($remove.Count -ne 1){throw 'actual before-placement removal branch missing'}
$install=$env:FG_FIXED
$source=$env:FG_CANDIDATE
$supportedPlacement=$true
$supportedContext=@{active_code_root=$env:FG_ACTIVE}
function Invoke-InstallationEvidenceChild {
 param($Label,$Executable,$Arguments)
 [IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'dispatch.json'),
   (@{executable=$Executable;arguments=$Arguments}|ConvertTo-Json -Compress))
 return @{ExitCode=0;Stdout='';Stderr=''}
}
Invoke-Expression $remove[0].Extent.Text
""", engine=engine, values={"FG_FIXED": str(packets.fixed),
                            "FG_ACTIVE": str(packets.active), "FG_CANDIDATE": str(packets.candidate)})
    assert result.returncode == 0, "isolated canonical removal dispatch failed"
    dispatch = json.loads((tmp_path / "dispatch.json").read_text(encoding="utf-8-sig"))
    host = Path(dispatch["arguments"][2]).parent.parent
    # Execute the selected host's actual generation/removal functions, with
    # finite OS lifecycle adapters and no installer or GUI entrypoint launch.
    assert packets.remove(host)["status"] == "PASS_DATA_PRESERVED"
    assert host == packets.active


@pytest.mark.parametrize('case', ['pointer', 'partial_control', 'state', 'active_record', 'active_code', 'source_code', 'source_manifest', 'wrong_build', 'trust_key', 'control_changed', 'rolled_back_sha'])
def test_updated_removal_rejects_forged_or_partial_proof(updated_packets, monkeypatch, case):
    import auto_update as update
    import current_user_onboarding as onboarding

    packets = updated_packets
    if case == "pointer":
        update.write_json_durable(packets.control / "active.json", {"schema": update.SCHEMA, "sha": "c" * 40})
    elif case == "partial_control":
        (packets.control / "policy.json").unlink()
    elif case in {'state', 'rolled_back_sha'}:
        state = update.read_json(packets.control / 'transition.json')
        if case == 'state':
            state['phase'] = 'SWITCHING'
        else:
            state.update(phase='ROLLED_BACK', previous_sha='a' * 40)
        update.write_json_durable(packets.control / 'transition.json', state)
    elif case in {"active_record", "active_code", "source_code", "trust_key"}:
        target = (packets.active / "bootstrap-integrity.json" if case == "active_record" else
                  packets.support / "app/data_generation_guard.py" if case == "source_code" else
                  packets.active / "app/update-manifest-key-config.json" if case == "trust_key" else
                  packets.active / "app/data_generation_guard.py")
        with target.open("ab") as stream:
            stream.write(b"\ninvalid proof bytes\n")
    elif case in {"source_manifest", "wrong_build"}:
        path = (packets.support if case == "source_manifest" else packets.active) / "portable-manifest.json"
        metadata = json.loads(path.read_bytes())
        metadata["source_commit"] = "c" * 40
        path.write_text(json.dumps(metadata), encoding="utf-8")
        if case == "wrong_build":
            (packets.support / "portable-manifest.json").write_bytes(path.read_bytes())
            _record_installed_packet(packets.root.parent, packets.active)
    else:
        verify = onboarding.verify_bootstrap_integrity

        def change_after_verify(*args, **kwargs):
            result = verify(*args, **kwargs)
            if args[0].app_root == packets.active:
                update.write_json_durable(packets.control / "active.json", {"schema": update.SCHEMA, "sha": "c" * 40})
            return result

        monkeypatch.setattr(onboarding, "verify_bootstrap_integrity", change_after_verify)
    markers = [path.read_bytes() for path in packets.markers]
    event = packets.seed.event.read_bytes()
    with pytest.raises(onboarding.CurrentUserOnboardingError):
        packets.remove()
    assert packets.seed.observed == []
    assert not packets.seed.paths.removal_report_path.exists()
    assert [path.read_bytes() for path in packets.markers] == markers
    assert packets.seed.event.read_bytes() == event

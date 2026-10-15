"""Support removal binds the executing stock packet to the installed record."""
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from tests.test_portable_data_generation import signed_packet, signed_proof


def _record_installed_packet(tmp_path, packet):
    import current_user_onboarding as onboarding
    from tests.powershell_contracts import run_functions

    source = Path(onboarding.__file__).resolve().parent
    literal = str(packet).replace("'", "''")
    result = run_functions(tmp_path, source / "tools/bootstrap_integrity.ps1", [
        "Get-StrictFullPath", "Get-RelativeCodePath", "Get-FileSha256", "Get-CodeInventory",
        "Get-InventoryAggregate", "Protect-InstallationText", "Assert-InstallationMachineMetadataNoSecrets",
        "Write-Utf8Json", "Write-BootstrapIntegrityRecord", "Invoke-ContainerAtomicReplaceOnce", "Invoke-ContainerAtomicReplace"], f"""
$BootstrapIntegritySchema='container-audit-bootstrap-integrity-v1'
$BootstrapIntegrityFileName='bootstrap-integrity.json'
[void](Write-BootstrapIntegrityRecord -Root '{literal}' -CodeRootIdentity '.')
""")
    assert result.returncode == 0, "official installed integrity record writer failed"


@pytest.fixture
def support_removal_packets(tmp_path, monkeypatch, signed_packet):
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    from tools import register_container_audit_worker_pc as registration

    installed = signed_packet()
    manifest_path = installed / "portable-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest.update(schema="container-audit-portable-tree-v1", source_tree="b" * 40)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    for module in (guard, onboarding):
        shutil.copyfile(module.__file__ if module is onboarding else Path(onboarding.__file__).parent / "data_generation_guard.py",
                        installed / "app" / Path(module.__file__).name)
    _record_installed_packet(tmp_path, installed)
    support = tmp_path / "support"
    shutil.copytree(installed, support, ignore=shutil.ignore_patterns("bootstrap-integrity.json"))
    monkeypatch.setattr(guard, "__file__", str(support / "app/data_generation_guard.py"))
    subject = "-".join(map(str, ("S", 1, 5, 21, 129)))
    monkeypatch.setattr(registration, "_current_user_sid", lambda: subject)
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "data")}
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", environment["CONTAINER_AUDIT_DATA_ROOT"])
    paths = onboarding.resolve_current_user_onboarding_paths(installed / "app", environ=environment)
    event = paths.data_root / "events/removal.csv"
    event.parent.mkdir(parents=True)
    event.write_bytes(b"event,quantity\nowned-removal,1\n")
    observed = []

    def remove():
        return onboarding.remove_current_user_setup(
            installed / "app", environ=environment,
            autostart_remover=lambda: observed.append("autostart") or {"status": "ABSENT"},
            relay_stopper=lambda _root: observed.append("relay") or {"status": "ABSENT"},
        )

    return SimpleNamespace(installed=installed, support=support, paths=paths, subject=subject,
                           remove=remove, observed=observed, event=event, environment=environment)


def _packet_bytes(packet):
    return {path.relative_to(packet).as_posix(): path.read_bytes() for path in packet.rglob("*") if path.is_file()}


def test_support_packet_without_installation_record_removes_same_release(support_removal_packets):
    import data_generation_guard as guard

    packets = support_removal_packets
    before = [_packet_bytes(packet) for packet in (packets.support, packets.installed)]
    event = packets.event.read_bytes()
    assert not (packets.support / "bootstrap-integrity.json").exists()
    with pytest.raises(ValueError):
        guard._runtime_release()
    report = packets.remove()
    assert report["status"] == "PASS_DATA_PRESERVED"
    assert packets.observed == ["autostart", "relay"]
    assert packets.event.read_bytes() == event
    assert [_packet_bytes(packet) for packet in (packets.support, packets.installed)] == before
    assert not (packets.paths.data_root / "data-generation.json").exists()
    # The proof belongs only to removal and cannot authorize ordinary startup.
    with pytest.raises(ValueError):
        guard._runtime_release()


@pytest.mark.parametrize("case", [
    "version", "build", "manifest", "signature", "code", "missing_record", "invalid_record",
    "invalid_signature_both", "missing_key_both", "invalid_support_record",
])
def test_support_removal_rejects_unproven_packet_before_mutation(tmp_path, support_removal_packets, case, capsys):
    import current_user_onboarding as onboarding

    packets = support_removal_packets
    installed_manifest = packets.installed / "portable-manifest.json"
    support_manifest = packets.support / "portable-manifest.json"
    if case in {"version", "build"}:
        metadata = json.loads(installed_manifest.read_bytes())
        metadata["version" if case == "version" else "source_commit"] = "v2.0.100" if case == "version" else "c" * 40
        installed_manifest.write_text(json.dumps(metadata), encoding="utf-8")
        if case == "version":
            (packets.installed / "app/Container_Audit.py").write_text('CURRENT_VERSION = "v2.0.100"\n', encoding="utf-8")
        _record_installed_packet(tmp_path, packets.installed)
    elif case in {"manifest", "signature", "invalid_signature_both"}:
        metadata = json.loads(support_manifest.read_bytes())
        if case == "manifest":
            metadata["data_generation_signed_manifest"]["data_compatible_min_version"] = "v2.0.97"
        else:
            metadata["data_generation_signature_hex"] = bytes(64).hex()
        support_manifest.write_text(json.dumps(metadata), encoding="utf-8")
        if case == "invalid_signature_both":
            installed_manifest.write_bytes(support_manifest.read_bytes())
            _record_installed_packet(tmp_path, packets.installed)
    elif case == "code":
        with (packets.support / "app/data_generation_guard.py").open("ab") as stream:
            stream.write(b"\n# different executing code\n")
    elif case == "missing_record":
        (packets.installed / "bootstrap-integrity.json").unlink()
    elif case == "invalid_record":
        (packets.installed / "bootstrap-integrity.json").write_text("{}", encoding="utf-8")
    elif case == "missing_key_both":
        for packet in (packets.support, packets.installed):
            (packet / "app/update-manifest-key-config.json").unlink()
        _record_installed_packet(tmp_path, packets.installed)
    elif case == "invalid_support_record":
        (packets.support / "bootstrap-integrity.json").write_text("{}", encoding="utf-8")
    before = [_packet_bytes(packet) for packet in (packets.support, packets.installed)]
    event = packets.event.read_bytes()
    with pytest.raises(onboarding.CurrentUserOnboardingError) as caught:
        packets.remove()
    assert onboarding.emit_installer_failure(caught.value, "current_user_removal") == 4
    public = json.loads(capsys.readouterr().err.split(onboarding.INSTALLER_FAILURE_PREFIX)[-1])
    assert public["reason_code"] == "DATA_GENERATION_UNKNOWN"
    assert packets.observed == []
    assert not packets.paths.removal_report_path.exists()
    assert packets.event.read_bytes() == event
    assert [_packet_bytes(packet) for packet in (packets.support, packets.installed)] == before


@pytest.mark.parametrize("same_version", [False, True])
def test_support_removal_preserves_generation_refusal(support_removal_packets, same_version, capsys):
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    from kmtech_shared import data_generation as generation

    packets = support_removal_packets
    markers = guard.marker_paths(packets.paths.data_root, packets.subject)
    for marker in markers:
        marker.parent.mkdir(parents=True, exist_ok=True)
        generation.record_generation(marker, "v2.0.99" if same_version else "v2.0.100",
                                     app_id="container_audit", subject_sid=packets.subject, build_id="c" * 40)
    before = [marker.read_bytes() for marker in markers]
    with pytest.raises(onboarding.CurrentUserOnboardingError) as caught:
        packets.remove()
    assert onboarding.emit_installer_failure(caught.value, "current_user_removal") == 4
    public = json.loads(capsys.readouterr().err.split(onboarding.INSTALLER_FAILURE_PREFIX)[-1])
    assert public["reason_code"] == ("DATA_GENERATION_UNKNOWN" if same_version else "DATA_GENERATION_REFUSED")
    assert [marker.read_bytes() for marker in markers] == before
    assert packets.observed == []
    assert not packets.paths.removal_report_path.exists()


def test_support_removal_can_use_matched_installed_record_without_compatibility_proof(tmp_path, support_removal_packets):
    packets = support_removal_packets
    for packet in (packets.support, packets.installed):
        path = packet / "portable-manifest.json"
        metadata = json.loads(path.read_bytes())
        metadata.pop("data_generation_signed_manifest")
        metadata.pop("data_generation_signature_hex")
        path.write_text(json.dumps(metadata), encoding="utf-8")
    _record_installed_packet(tmp_path, packets.installed)
    assert packets.remove()["status"] == "PASS_DATA_PRESERVED"


def test_support_removal_inventory_and_signature_proof_stay_outside_admission(support_removal_packets, monkeypatch):
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    import writer_session_fence as fence

    depths = []
    hash_file = onboarding._file_sha256
    verify_compatibility = guard.verified_private_compatibility

    def observed_hash(*args, **kwargs):
        depths.append(getattr(fence._WRITER_LOCAL, "depth", 0))
        return hash_file(*args, **kwargs)

    def observed_signature(*args, **kwargs):
        depths.append(getattr(fence._WRITER_LOCAL, "depth", 0))
        return verify_compatibility(*args, **kwargs)

    monkeypatch.setattr(onboarding, "_file_sha256", observed_hash)
    monkeypatch.setattr(guard, "verified_private_compatibility", observed_signature)
    assert support_removal_packets.remove()["status"] == "PASS_DATA_PRESERVED"
    assert depths and set(depths) == {0}


def test_support_removal_preserves_real_writer_fence_exception(support_removal_packets, capsys):
    import current_user_onboarding as onboarding
    import writer_session_fence as fence

    packets = support_removal_packets
    root = fence.canonical_control_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / fence.ACTIVE_FILENAME).write_text("{}", encoding="utf-8")
    with pytest.raises(fence.WriterFenceError) as caught:
        packets.remove()
    assert onboarding.emit_installer_failure(caught.value, "current_user_removal") == 23
    public = json.loads(capsys.readouterr().err.split(onboarding.INSTALLER_FAILURE_PREFIX)[-1])
    assert public["reason_code"] == caught.value.code
    assert packets.observed == []
    assert not packets.paths.removal_report_path.exists()


def test_installed_packet_removal_uses_existing_integrity_path(support_removal_packets, monkeypatch):
    import data_generation_guard as guard

    packets = support_removal_packets
    monkeypatch.setattr(guard, "__file__", str(packets.installed / "app/data_generation_guard.py"))
    portable_release = guard._portable_runtime_release
    observed = []

    def verify_installed():
        observed.append("installed_integrity")
        return portable_release()

    monkeypatch.setattr(guard, "_portable_runtime_release", verify_installed)
    event = packets.event.read_bytes()
    assert packets.remove()["status"] == "PASS_DATA_PRESERVED"
    assert observed
    assert packets.event.read_bytes() == event
    assert guard._SUPPORT_REMOVAL_RELEASE.get() is None

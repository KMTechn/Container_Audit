"""A stock Python packet must verify its code entrypoint without a frozen EXE."""
import json
from pathlib import Path

import pytest


@pytest.fixture
def signed_proof():
    """Ephemeral test keys only; exercise the product's actual ES256 verifier."""
    from update_service import canonical_manifest_bytes
    from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair

    def make(**changes):
        manifest = {
            "schema_version": "kmtech-private-update-manifest-v1", "manifest_version": 1,
            "signature_version": "es256-v1", "app_id": "Container_Audit",
            "package_id": "Container_Audit", "version": "v2.0.99",
            "source_commit": "a" * 40, "data_compatible_min_version": "v2.0.98",
        }
        manifest.update(changes)
        with P256KeyPair.generate() as key:
            signature = key.sign_es256(canonical_manifest_bytes(manifest))
            configuration = key.public_jwk
        return manifest, signature, configuration

    return make


@pytest.fixture
def signed_packet(tmp_path, monkeypatch, signed_proof):
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    from tests.powershell_contracts import run_functions

    source = Path(onboarding.__file__).resolve().parent
    packet = tmp_path / "signed-packet"
    app = packet / "app"
    app.mkdir(parents=True)
    (app / "Container_Audit.py").write_text('CURRENT_VERSION = "v2.0.99"\n', encoding="utf-8")
    monkeypatch.setattr(guard, "__file__", str(app / "data_generation_guard.py"))
    monkeypatch.setattr(guard, "_PORTABLE_RELEASE_CACHE", {})

    def make(case="valid"):
        changes = {
            "wrong_app": {"app_id": "Label_Match"},
            "wrong_package": {"package_id": "Label_Match"},
            "wrong_version": {"version": "v2.0.100"},
            "wrong_build": {"source_commit": "b" * 40},
            "future_floor": {"data_compatible_min_version": "v2.0.100"},
            "invalid_floor": {"data_compatible_min_version": "invalid"},
            "wrong_schema": {"schema_version": "other-schema"},
            "wrong_manifest_version": {"manifest_version": 2},
            "legacy_signature": {"signature_version": "ed25519-v1"},
        }.get(case, {})
        proof, signature, configuration = signed_proof(**changes)
        if case == "no_floor":
            proof.pop("data_compatible_min_version")
            from update_service import canonical_manifest_bytes
            from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair
            with P256KeyPair.generate() as key:
                signature = key.sign_es256(canonical_manifest_bytes(proof))
                configuration = key.public_jwk
        metadata = {"version": "v2.0.99", "source_commit": "a" * 40,
                    "data_compatible_min_version": "v2.0.33",
                    "data_generation_signed_manifest": proof,
                    "data_generation_signature_hex": signature.hex()}
        if case == "tampered":
            proof["data_compatible_min_version"] = "v2.0.97"
        elif case == "missing_signature":
            metadata.pop("data_generation_signature_hex")
        elif case == "invalid_signature_hex":
            metadata["data_generation_signature_hex"] = "not-a-signature"
        elif case == "invalid_proof":
            metadata["data_generation_signed_manifest"] = []
        elif case == "unsigned":
            metadata.pop("data_generation_signed_manifest")
            metadata.pop("data_generation_signature_hex")
        elif case == "wrong_key":
            configuration = signed_proof()[2]
        key_path = app / "update-manifest-key-config.json"
        if case == "onboarding":
            (packet / "Container_Audit.exe").write_bytes(b"synthetic frozen entrypoint; never execute")
        if case != "missing_key":
            key_document = {
                "schema": "container-audit-update-key-config-v1",
                "manifest_public_key": configuration,
            }
            if case == "wrong_key_schema":
                key_document["schema"] = "other-schema"
            key_path.write_text(json.dumps(key_document), encoding="utf-8")
        (packet / "portable-manifest.json").write_text(json.dumps(metadata), encoding="utf-8")
        literal = str(packet).replace("'", "''")
        result = run_functions(tmp_path, source / "tools/bootstrap_integrity.ps1", [
            "Get-StrictFullPath", "Get-RelativeCodePath", "Get-FileSha256", "Get-CodeInventory",
            "Get-InventoryAggregate", "Protect-InstallationText",
            "Assert-InstallationMachineMetadataNoSecrets", "Write-Utf8Json",
            "Write-BootstrapIntegrityRecord",
        ], f"""
$BootstrapIntegritySchema='container-audit-bootstrap-integrity-v1'
$BootstrapIntegrityFileName='bootstrap-integrity.json'
[void](Write-BootstrapIntegrityRecord -Root '{literal}' -CodeRootIdentity '.')
""")
        assert result.returncode == 0, "official integrity record writer failed"
        return packet

    return make


@pytest.mark.parametrize("case", [
    "valid", "tampered", "wrong_app", "wrong_package", "wrong_version", "wrong_build",
    "future_floor", "invalid_floor", "wrong_schema", "wrong_manifest_version",
    "legacy_signature", "missing_key", "wrong_key", "wrong_key_schema", "missing_signature", "invalid_signature_hex",
    "invalid_proof", "unsigned", "no_floor",
])
def test_installed_signed_floor_or_self_fallback(signed_packet, case):
    import data_generation_guard as guard

    signed_packet(case)
    release = guard._runtime_release()
    assert release["version"] == "v2.0.99" and release["build_id"] == "a" * 40
    assert (release["data_compatible_min_version"], release["compatibility_verified"]) == (
        ("v2.0.98", True) if case == "valid" else ("v2.0.99", False))


def test_signed_floor_is_warmed_once_outside_admission(tmp_path, signed_packet, monkeypatch):
    import data_generation_guard as guard
    import update_service
    import writer_session_fence as fence
    from tools import register_container_audit_worker_pc as registration

    signed_packet()
    observed = []
    verify = update_service.verify_update_manifest_signature

    def verify_observed(*args, **kwargs):
        observed.append(getattr(fence._WRITER_LOCAL, "depth", 0))
        return verify(*args, **kwargs)

    monkeypatch.setattr(update_service, "verify_update_manifest_signature", verify_observed)
    monkeypatch.setattr(registration, "_current_user_sid", lambda: "S-1-5-21-219")
    guard.warm_runtime_release()
    first = guard._runtime_release()
    first["data_compatible_min_version"] = "v2.0.33"
    assert guard._runtime_release()["data_compatible_min_version"] == "v2.0.98"
    guard.record_before_data_open(tmp_path / "data")
    assert json.loads((tmp_path / "data/data-generation.json").read_bytes())["compatibility_verified"] is True
    assert observed == [0]


@pytest.mark.parametrize("case,expected", [("valid", "ALLOW"), ("unsigned", "REFUSE")])
def test_installed_floor_records_and_probes_previous_version(tmp_path, signed_packet, case, expected):
    import data_generation_guard as guard
    from kmtech_shared import data_generation as generation

    signed_packet(case)
    release = guard._runtime_release()
    identity = {"app_id": "container_audit", "subject_sid": "S-1-5-21-219"}
    markers = [tmp_path / "control.json", tmp_path / "owner.json"]
    for marker in markers:
        generation.record_generation(marker, **identity, **release)
    before = [marker.read_bytes() for marker in markers]
    decision = generation.probe_downgrade(markers, "v2.0.98", target_build_id="b" * 40, **identity)
    assert decision["status"] == expected
    assert [marker.read_bytes() for marker in markers] == before
    # An existing same-build marker cannot gain a lower floor retrospectively.
    old = tmp_path / "already-opened.json"
    generation.record_generation(old, "v2.0.99", build_id="a" * 40, **identity)
    original = old.read_bytes()
    generation.record_generation(old, **identity, **release)
    assert old.read_bytes() == original
    assert generation.probe_downgrade([old], "v2.0.98", target_build_id="b" * 40, **identity)["status"] == "REFUSE"


def test_python_packet_generation_identity(tmp_path, monkeypatch):
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    from tests.powershell_contracts import run_functions

    source_root = Path(onboarding.__file__).resolve().parent
    packet = tmp_path / "packet"
    app = packet / "app"
    app.mkdir(parents=True)
    (app / "Container_Audit.py").write_text('CURRENT_VERSION = "v2.0.99"\n')
    (app / "data_generation_guard.py").write_text("# copied runtime code\n")
    (packet / "portable-manifest.json").write_text(json.dumps({
        "version": "v2.0.99", "source_commit": "a" * 40}))
    literal = str(packet).replace("'", "''")
    result = run_functions(tmp_path, source_root / "tools/bootstrap_integrity.ps1",
        ["Get-StrictFullPath", "Get-RelativeCodePath", "Get-FileSha256", "Get-CodeInventory",
         "Get-InventoryAggregate", "Protect-InstallationText",
         "Assert-InstallationMachineMetadataNoSecrets", "Write-Utf8Json",
         "Write-BootstrapIntegrityRecord"], f"""
$BootstrapIntegritySchema='container-audit-bootstrap-integrity-v1'
$BootstrapIntegrityFileName='bootstrap-integrity.json'
[void](Write-BootstrapIntegrityRecord -Root '{literal}' -CodeRootIdentity '.')
""")
    assert result.returncode == 0, result.stdout + result.stderr
    monkeypatch.setattr(guard, "__file__", str(app / "data_generation_guard.py"))
    assert guard._runtime_release() == {"version": "v2.0.99", "build_id": "a" * 40,
        "data_compatible_min_version": "v2.0.99", "compatibility_verified": False}
def test_stock_application_contains_data_generation_adapter(tmp_path):
    from tools import build_portable_release_candidate as builder

    source = Path(builder.__file__).resolve().parents[1]
    target = tmp_path / "copied-app"
    builder._copy_application(source, target)
    assert (target / "data_generation_guard.py").read_bytes() == (source / "data_generation_guard.py").read_bytes()
    assert (target / "tools/check_release_version.py").is_file()
    assert (target / "kmtech_shared/powershell/data_generation.ps1").is_file()


@pytest.fixture
def metadata_build(tmp_path, monkeypatch, signed_proof):
    """Run the builder's metadata path with deterministic packaging inputs."""
    import subprocess
    from types import SimpleNamespace
    from tools import build_portable_release_candidate as builder

    source = tmp_path / "source"
    source.mkdir()
    (source / "Container_Audit.py").write_text('CURRENT_VERSION = "v2.0.99"\n', encoding="utf-8")
    for relative in {item[0] for item in builder.PORTABLE_INSTALL_ASSETS} | {"portable/launch-container-audit.cmd"}:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative + "\n", encoding="utf-8")
    proof, signature, configuration = signed_proof()
    manifest_path = tmp_path / "manifest.json"
    signature_path = tmp_path / "manifest.sig"
    manifest_path.write_text(json.dumps(proof), encoding="utf-8")
    signature_path.write_bytes(signature)
    run = subprocess.run

    def shared_check(command, *args, **kwargs):
        if any(Path(str(item)).name == "check_kmtech_shared.py" for item in command):
            return SimpleNamespace(returncode=0, stderr="")
        return run(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", shared_check)

    def prepare(module):
        def runtime(_python_home, target):
            target.mkdir(parents=True)
            (target / "pythonw.exe").write_bytes(b"synthetic runtime")

        def application(_root, target):
            target.mkdir(parents=True)
            (target / "Container_Audit.py").write_bytes((source / "Container_Audit.py").read_bytes())
            return []

        monkeypatch.setattr(module, "_assert_clean_source", lambda root: None)
        monkeypatch.setattr(module, "_assert_writer_sink_inventory", lambda root: {"inventory_sha256": "c" * 64})
        monkeypatch.setattr(module, "_runtime_source", runtime)
        monkeypatch.setattr(module, "_copy_application", application)
        monkeypatch.setattr(module, "_copy_third_party", lambda target: {})
        monkeypatch.setattr(module, "_assert_portable_import_closure", lambda *args: None)
        monkeypatch.setattr(module, "_app_native_inventory", lambda root: [])
        monkeypatch.setattr(module, "_git_value", lambda root, expression: "b" * 40 if "tree" in expression else "a" * 40)

    prepare(builder)
    return SimpleNamespace(builder=builder, source=source, prepare=prepare,
        runtime=tmp_path / "runtime-home", configuration=json.dumps(configuration),
        manifest=manifest_path, signature=signature_path)


@pytest.mark.parametrize("floor", [None, "v2.0.98"])
def test_builder_without_proof_preserves_baseline_metadata_bytes(tmp_path, metadata_build, floor):
    import importlib.util
    import subprocess

    source_root = Path(__file__).resolve().parents[1]
    # Row 1 adds a required PS module to the package. Compare against the
    # committed state immediately before row 6 so its asset counts match.
    baseline_bytes = subprocess.check_output([
        "git", "show", "9ab73f75c8a6c2a8ec54e82236723be66221446a:tools/build_portable_release_candidate.py",
    ], cwd=source_root)
    baseline_path = tmp_path / "baseline_builder.py"
    baseline_path.write_bytes(baseline_bytes)
    spec = importlib.util.spec_from_file_location("row6_baseline_builder", baseline_path)
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    metadata_build.prepare(baseline)
    outputs = [tmp_path / "baseline", tmp_path / "current"]
    for module, output in zip((baseline, metadata_build.builder), outputs):
        module.build(metadata_build.source, metadata_build.runtime, output,
                     update_manifest_public_key_config=metadata_build.configuration,
                     data_compatible_min_version=floor)
    identical = ((outputs[0] / "portable-manifest.json").read_bytes()
                 == (outputs[1] / "portable-manifest.json").read_bytes())
    assert identical, "no-proof metadata differs from committed baseline bytes"


def test_previous_portable_reader_ignores_added_proof_fields(tmp_path, signed_packet):
    import importlib.util
    import subprocess

    packet = signed_packet()
    baseline_path = tmp_path / "baseline_guard.py"
    baseline_path.write_bytes(subprocess.check_output([
        "git", "show", "f9c0d9babba8aa1316f390556f93d2812e38ec83:data_generation_guard.py",
    ], cwd=Path(__file__).resolve().parents[1]))
    spec = importlib.util.spec_from_file_location("row6_baseline_guard", baseline_path)
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    baseline.__file__ = str(packet / "app/data_generation_guard.py")
    assert baseline._runtime_release() == {
        "version": "v2.0.99", "build_id": "a" * 40,
        "data_compatible_min_version": "v2.0.99", "compatibility_verified": False,
    }


def test_builder_embeds_validated_signed_floor(tmp_path, metadata_build):
    build = metadata_build
    output = tmp_path / "built"
    metadata = build.builder.build(build.source, build.runtime, output,
        update_manifest_public_key_config=build.configuration,
        data_generation_update_manifest=build.manifest,
        data_generation_update_signature=build.signature)
    assert metadata["data_compatible_min_version"] == "v2.0.98"
    matches = (metadata["data_generation_signed_manifest"] == json.loads(build.manifest.read_bytes())
               and metadata["data_generation_signature_hex"] == build.signature.read_bytes().hex())
    assert matches, "builder did not preserve the detached proof"
    assert (output / "portable-manifest.json").stat().st_size <= 65536


@pytest.mark.parametrize("case", ["manifest_only", "signature_only", "tampered", "wrong_build", "oversized"])
def test_builder_rejects_invalid_proof_before_creating_output(tmp_path, metadata_build, signed_proof, case):
    build = metadata_build
    if case == "tampered":
        proof = json.loads(build.manifest.read_bytes())
        proof["data_compatible_min_version"] = "v2.0.97"
        build.manifest.write_text(json.dumps(proof), encoding="utf-8")
    elif case == "wrong_build":
        proof, signature, configuration = signed_proof(source_commit="d" * 40)
        build.manifest.write_text(json.dumps(proof), encoding="utf-8")
        build.signature.write_bytes(signature)
        build.configuration = json.dumps(configuration)
    elif case == "oversized":
        build.manifest.write_bytes(b" " * (1024 * 1024 + 1))
    output = tmp_path / "rejected"
    with pytest.raises(build.builder.PortableBuildError, match="private compatibility"):
        build.builder.build(build.source, build.runtime, output,
            update_manifest_public_key_config=build.configuration,
            data_generation_update_manifest=None if case == "signature_only" else build.manifest,
            data_generation_update_signature=None if case == "manifest_only" else build.signature)
    assert not output.exists()


def test_builder_parses_signed_floor_arguments(tmp_path):
    from tools import build_portable_release_candidate as builder

    args = builder.parse_args(["--output", str(tmp_path / "built"),
        "--data-generation-update-manifest", str(tmp_path / "manifest.json"),
        "--data-generation-update-signature", str(tmp_path / "manifest.sig")])
    assert args.data_generation_update_manifest == tmp_path / "manifest.json"
    assert args.data_generation_update_signature == tmp_path / "manifest.sig"


def test_builder_rejects_signed_metadata_above_reader_bound(tmp_path, metadata_build, signed_proof):
    build = metadata_build
    # The valid input is below 1 MiB; JSON escaping makes portable metadata
    # exceed the existing 64 KiB runtime reader contract.
    proof, signature, configuration = signed_proof(notes="\u00fc" * 15000)
    build.manifest.write_text(json.dumps(proof), encoding="utf-8")
    build.signature.write_bytes(signature)
    with pytest.raises(build.builder.PortableBuildError, match="runtime bound"):
        build.builder.build(build.source, build.runtime, tmp_path / "oversized-packet",
            update_manifest_public_key_config=json.dumps(configuration),
            data_generation_update_manifest=build.manifest,
            data_generation_update_signature=build.signature)


def test_crypto_api_failure_keeps_business_open(tmp_path, signed_packet, monkeypatch, caplog):
    import data_generation_guard as guard
    import update_service
    from tools import register_container_audit_worker_pc as registration
    signed_packet()
    observed = []
    def failed(*args, **kwargs):
        observed.append(1)
        raise RuntimeError("synthetic crypto API failure")
    monkeypatch.setattr(update_service, "verify_update_manifest_signature", failed)
    monkeypatch.setattr(registration, "_current_user_sid", lambda: "S-1-5-21-219")
    guard.warm_runtime_release()
    release = guard._runtime_release()
    assert (release["data_compatible_min_version"], release["compatibility_verified"]) == ("v2.0.99", False)
    guard.record_before_data_open(tmp_path / "data")
    assert json.loads((tmp_path / "data/data-generation.json").read_bytes())["compatibility_verified"] is False
    assert observed == [1]
    assert len(caplog.records) == 1 and "synthetic crypto" not in caplog.text


def test_installer_onboarding_verifies_floor_before_admission(tmp_path, signed_packet, monkeypatch):
    import current_user_onboarding as onboarding
    import update_service
    import writer_session_fence as fence
    from tests.test_current_user_onboarding import (
        _ready_state, _profile_loader, _credential_loader, _ledger_factory, _autostart, _relay_start,
        _FakeExistingPossessionKey,
    )
    from tools import register_container_audit_worker_pc as registration
    packet = signed_packet("onboarding")
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "owner")}
    paths = onboarding.resolve_current_user_onboarding_paths(packet, environ=environment)
    _ready_state(paths)
    monkeypatch.setattr(onboarding.PersistentPossessionKey, "open_existing",
        classmethod(lambda _cls, *args, **kwargs: _FakeExistingPossessionKey()))
    monkeypatch.setattr(registration, "_current_user_sid", lambda: "S-1-5-21-219")
    observed = []
    verify = update_service.verify_update_manifest_signature
    def measured(*args, **kwargs):
        observed.append(getattr(fence._WRITER_LOCAL, "depth", 0))
        return verify(*args, **kwargs)
    monkeypatch.setattr(update_service, "verify_update_manifest_signature", measured)
    def forbidden(*args, **kwargs):
        raise AssertionError("READY fixture must not register or contact a server")
    report = onboarding.onboard_current_user(packet, environ=environment, require_bootstrap_integrity=True,
        registration_runner=forbidden, profile_loader=_profile_loader, credential_loader=_credential_loader,
        ledger_factory=_ledger_factory, autostart_installer=_autostart, relay_launcher=_relay_start)
    assert report["status"] == "READY"
    assert json.loads((paths.data_root / "data-generation.json").read_bytes())["compatibility_verified"] is True
    assert observed == [0]


def test_real_feed_floor_builder_integrity_and_runtime(tmp_path, metadata_build, signed_proof, monkeypatch):
    """Actual feed shape passes 64 KiB and the official metadata secret check."""
    import current_user_onboarding as onboarding
    import data_generation_guard as guard
    from tests.powershell_contracts import run_functions
    from tests.test_update_service import _private_update_manifest
    from types import SimpleNamespace
    build = metadata_build
    proof, signature, configuration = signed_proof(**_private_update_manifest(
        version="v2.0.99", url="https://updates.example.invalid/Container_Audit-v2.0.99.zip"))
    build.manifest.write_text(json.dumps(proof), encoding="utf-8")
    build.signature.write_bytes(signature)
    output = tmp_path / "real-feed-packet"
    metadata = build.builder.build(build.source, build.runtime, output,
        update_manifest_public_key_config=json.dumps(configuration),
        data_generation_update_manifest=build.manifest, data_generation_update_signature=build.signature)
    assert {"artifact", "archive", "install", "rollout"} <= metadata["data_generation_signed_manifest"].keys()
    assert (output / "portable-manifest.json").stat().st_size <= 65536
    literal = str(output).replace("'", "''")
    result = run_functions(tmp_path, Path(onboarding.__file__).resolve().parent / "tools/bootstrap_integrity.ps1", [
        "Get-StrictFullPath", "Get-RelativeCodePath", "Get-FileSha256", "Get-CodeInventory",
        "Get-InventoryAggregate", "Protect-InstallationText", "Assert-InstallationMachineMetadataNoSecrets",
        "Write-Utf8Json", "Write-BootstrapIntegrityRecord"], f"""
$BootstrapIntegritySchema='container-audit-bootstrap-integrity-v1'
$BootstrapIntegrityFileName='bootstrap-integrity.json'
[void](Write-BootstrapIntegrityRecord -Root '{literal}' -CodeRootIdentity '.')
""")
    assert result.returncode == 0, "official size/secret producer rejected actual feed shape"
    detail = onboarding.verify_bootstrap_integrity(SimpleNamespace(app_root=output,
        bootstrap_integrity_path=output / "bootstrap-integrity.json"), required=True,
        expected_entrypoint="app/Container_Audit.py")
    assert detail["status"] == "PASS"
    record = json.loads((output / "bootstrap-integrity.json").read_bytes())
    assert any(row["path"] == "app/update-manifest-key-config.json" for row in record["files"])
    monkeypatch.setattr(guard, "__file__", str(output / "app/data_generation_guard.py"))
    monkeypatch.setattr(guard, "_PORTABLE_RELEASE_CACHE", {})
    release = guard._runtime_release()
    assert (release["data_compatible_min_version"], release["compatibility_verified"]) == ("v2.0.98", True)

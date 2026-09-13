from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "derive_container_writer_sinks.py"
SNAPSHOT = ROOT / "tools" / "container_writer_sink_inventory.json"
EXPECTED_UNCOVERED_NODES: list[str] = []


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "derive_container_writer_sinks",
        SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_container_writer_sink_inventory_matches_snapshot() -> None:
    module = _load_module()
    expected = module.derive_inventory(ROOT)
    actual = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert actual == expected


def test_byte_exact_inventory_outputs_disable_checkout_eol_conversion() -> None:
    module = _load_module()
    relative_paths = tuple(
        Path(path).as_posix() for path in module.BYTE_EXACT_CHECKOUT_PATHS
    )

    assert relative_paths
    assert len(relative_paths) == len(set(relative_paths))
    for relative_path in relative_paths:
        completed = subprocess.run(
            ["git", "check-attr", "text", "eol", "--", relative_path],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        attributes = {
            name: value
            for _path, name, value in (
                line.split(": ", 2)
                for line in completed.stdout.splitlines()
                if line.strip()
            )
        }
        assert attributes.get("text") == "unset" or attributes.get("eol") == "lf"


def test_container_writer_sink_inventory_has_expected_current_findings() -> None:
    payload = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    module = _load_module()

    assert payload["schema_version"] == "container-audit-writer-sink-inventory-v8"
    assert payload["inventory_sha256"] == module._inventory_sha256(payload)
    assert payload["entrypoint_modules"] == [
        path.as_posix() for path in module._discover_shipped_application_paths(ROOT)
    ]
    shipped_application_sources = {
        path.as_posix() for path in module._discover_shipped_application_paths(ROOT)
    }
    assert shipped_application_sources <= set(payload["closure_modules"])
    assert payload["entrypoint_derivation"].startswith("all root Python files")
    assert payload["powershell_guard_failures"] == []
    assert payload["caller_fence_reference_failures"] == []
    powershell_files = {
        row["file"]: row
        for row in payload["powershell_execution_inventory"]["files"]
    }
    assert powershell_files["INSTALL_CANONICAL_PORTABLE.ps1"]["entry_guard"][
        "release_name"
    ] == "Exit-ContainerWriterSessionAuthority"
    assert powershell_files["INSTALL_CANONICAL_PORTABLE.ps1"]["entry_guard"][
        "release_line"
    ] > powershell_files["INSTALL_CANONICAL_PORTABLE.ps1"]["entry_guard"][
        "guard_line"
    ]
    assert powershell_files["INSTALL_THIS_PC.ps1"]["entry_guard"][
        "release_name"
    ] == "Exit-ContainerWriterAdmission"
    assert powershell_files["INSTALL_THIS_PC.ps1"]["entry_guard"][
        "release_line"
    ] > powershell_files["INSTALL_THIS_PC.ps1"]["entry_guard"]["guard_line"]
    assert powershell_files["tools/container_writer_session.ps1"]["entry_guard"][
        "release_name"
    ] == ""
    assert powershell_files["tools/container_writer_session.ps1"]["entry_guard"][
        "release_line"
    ] is None
    function_proofs = {
        (row["file"], row["function"]): row
        for row in payload["powershell_execution_inventory"][
            "function_guard_proofs"
        ]
    }
    selftest_proof = function_proofs[
        (
            "tools/container_writer_session.ps1",
            "Invoke-ContainerWriterSessionSelfTest",
        )
    ]
    assert selftest_proof["non_production_only"] is True
    assert selftest_proof["guard_name"] == "non_production_mode"
    assert all(
        proof["guarded"] is True
        for proof in function_proofs.values()
        if proof["production_reachable"] is True
    )
    assert payload["coverage_summary"]["uncovered_mutation_function_count"] == len(
        payload["uncovered_direct_mutation_functions"]
    )
    assert payload["coverage_summary"]["closure_direct_mutation_function_count"] == len(
        payload["closure_direct_mutation_functions"]
    )
    assert payload["coverage_summary"]["sink_function_count"] == len(
        payload["writer_sinks"]
    )
    assert payload["coverage_summary"] == {
        "closure_module_count": len(payload["closure_modules"]),
        "closure_direct_mutation_function_count": len(
            payload["closure_direct_mutation_functions"]
        ),
        "external_process_mutation_site_count": sum(
            1
            for row in payload["closure_direct_mutation_functions"]
            for site in row["mutation_sites"]
            if site["category"] == "external_process"
        ),
        "python_external_control_literal_site_count": len(
            payload["python_external_control_commands"]["literal_sites"]
        ),
        "sink_function_count": len(payload["writer_sinks"]),
        "powershell_sink_count": len(payload["powershell_writer_sinks"]),
        "total_cross_language_sink_count": len(payload["writer_sinks"])
        + len(payload["powershell_writer_sinks"]),
        "powershell_mutation_scope_count": len(
            payload["powershell_execution_inventory"]["mutation_scopes"]
        ),
        "powershell_direct_mutation_site_count": len(
            payload["powershell_execution_inventory"]["direct_mutation_sites"]
        ),
        "powershell_execution_site_count": len(
            payload["powershell_execution_inventory"]["execution_sites"]
        ),
        "powershell_execution_site_counts_by_kind": {
            kind: count
            for kind, count in payload["powershell_execution_inventory"][
                "site_counts_by_kind"
            ].items()
            if kind
            in {
                "call_operator",
                "com_wmi_process_create",
                "dot_source",
                "dotnet_process_start",
                "invoke_expression",
                "native_command",
                "native_process_api",
                "reflective_invocation",
                "scheduler_com",
                "service_control_api",
                "start_process",
            }
        },
        "scheduled_task_mutation_site_count": len(
            payload["powershell_scheduled_task_guards"]["mutation_sites"]
        ),
        "trusted_control_plane_mutation_count": len(
            payload["trusted_control_plane_mutations"]
        ),
        "uncovered_mutation_function_count": len(
            payload["uncovered_direct_mutation_functions"]
        ),
        "caller_fence_reference_failure_count": len(
            payload["caller_fence_reference_failures"]
        ),
    }
    assert payload["detector_limitations"] == [
        "Discovery is syntactic over the shipped local import closure and does not execute code.",
        "SQL mutation detection requires a directly supplied mutating SQL literal or constant-only f-string at the call site.",
        "Path-method mutation detection is conservative and requires static path-like receiver evidence.",
        "HTTP network mutation detection conservatively treats calls named post or request as writer sites.",
        "External process creation is conservatively treated as a writer boundary; static Python literals are also scanned for scheduled-task and service control commands.",
        "PowerShell discovery derives the six shipped portable PowerShell assets from PORTABLE_INSTALL_ASSETS and records dot-source boundaries; it does not execute PowerShell or recursively interpret sourced code.",
        "PowerShell Start-Process/Invoke-Item, Invoke-Expression/IEX, call-operator, direct script/native command, module import, explicit COM/WMI or native process creation, explicit .NET Process.Start, scheduler COM, service-control, runspace/job/event-action, and reflection primitives are conservatively treated as writer boundaries.",
        "A dynamic PowerShell invocation primitive can be detected and denied when unfenced, but its runtime-computed target or decoded payload cannot in general be resolved statically.",
        "PowerShell guard attribution enforces one bounded top-level guard lifetime and direct intra-file function-call reachability, but remains syntactic and does not prove computed or cross-module calls, alias resolution, module dispatch, or every multiline/here-string control-flow relationship.",
        "Runtime-generated aliases, imported command redefinitions, encrypted or downloaded code, native exports reached through computed reflection, and process creation hidden behind unknown modules remain unobservable statically and require runtime admission plus review.",
    ]

    uncovered_nodes = [
        row["node"] for row in payload["uncovered_direct_mutation_functions"]
    ]
    assert uncovered_nodes == EXPECTED_UNCOVERED_NODES
    covered_nodes = [
        row["node"]
        for row in payload["closure_direct_mutation_functions"]
        if row["coverage_status"] == "covered"
    ]
    assert all(
        row["coverage_status"] == "covered"
        for row in payload["closure_direct_mutation_functions"]
    )
    assert "event_log_store.EventLogOutbox.drain" in covered_nodes
    assert "direct_sync_auto_bootstrap._write_json" in covered_nodes
    assert "event_log_store._interprocess_file_lock" in covered_nodes
    assert "event_log_store._append_event_log_entry_unlocked" in covered_nodes
    assert "transfer_seal.TransferSealStore._initialize" in covered_nodes
    assert "kmtech_factory_contracts.active_work_probe.cli._create_new_fsynced" in covered_nodes
    assert "tools.direct_sync_relay_operator._write_json_atomic" in covered_nodes
    assert "tools.direct_sync_relay_install_pack._run_command" in covered_nodes
    assert payload["coverage_summary"]["external_process_mutation_site_count"] > 0
    external_commands = payload["python_external_control_commands"]
    assert {"Register-ScheduledTask", "schtasks.exe"} <= set(
        external_commands["commands"]
    )
    assert any(
        row["file"] == "tools/direct_sync_relay_install_pack.py"
        and "Register-ScheduledTask" in row["commands"]
        for row in external_commands["literal_sites"]
    )
    assert payload["powershell_writer_sinks"] == [
        {
            "file": "INSTALL_THIS_PC.ps1",
            "source": "canonical_code_placement",
            "guard_name": "Enter-ContainerPlacementWriterFence",
            "guard_line": next(
                row["guard_line"]
                for row in payload["powershell_execution_inventory"][
                    "script_entrypoints"
                ]
                if row["file"] == "INSTALL_THIS_PC.ps1"
            ),
            "release_name": "Exit-ContainerWriterAdmission",
            "release_line": next(
                row["release_line"]
                for row in payload["powershell_execution_inventory"][
                    "script_entrypoints"
                ]
                if row["file"] == "INSTALL_THIS_PC.ps1"
            ),
            "guarded": True,
            "writer_site_count": next(
                row["writer_site_count"]
                for row in payload["powershell_execution_inventory"][
                    "script_entrypoints"
                ]
                if row["file"] == "INSTALL_THIS_PC.ps1"
            ),
            "writer_site_kinds": next(
                row["writer_site_kinds"]
                for row in payload["powershell_execution_inventory"][
                    "script_entrypoints"
                ]
                if row["file"] == "INSTALL_THIS_PC.ps1"
            ),
        }
    ]
    assert "canonical_code_placement" in payload["writer_sink_sources"]
    assert payload["powershell_execution_inventory"]["asset_derivation"] == (
        "portable_builder.PORTABLE_INSTALL_ASSETS"
    )
    assert payload["powershell_execution_inventory"]["asset_paths"] == [
        path.as_posix() for path in module._discover_shipped_powershell_paths(ROOT)
    ]
    assert payload["coverage_summary"]["powershell_execution_site_counts_by_kind"] == {
        "call_operator": 22,
        "com_wmi_process_create": 1,
        "dot_source": 10,
        "start_process": 3,
    }
    helper_calls = [
        row for row in payload["powershell_execution_inventory"]["execution_sites"]
        if row["file"] == "INSTALL_CANONICAL_PORTABLE.ps1"
        and row["kind"] == "call_operator" and row["target"] == "$winps"
    ]
    # Five delegated bootstrap invocations (including public late restore) and
    # two read-only integrity probes.
    assert len(helper_calls) == 7
    assert all(row["guarded"] for row in helper_calls)
    assert {row["guard_name"] for row in helper_calls} == {"Enter-ContainerWriterSessionAuthority"}
    bootstrap_loads = [
        row for row in payload["powershell_execution_inventory"]["execution_sites"]
        if row["file"] == "INSTALL_CANONICAL_PORTABLE.ps1"
        and row["kind"] == "dot_source"
        and row["target"] == "$BootstrapIntegrityFunctions"
    ]
    assert len(bootstrap_loads) == 2
    assert all(row["guarded"] is True for row in bootstrap_loads)
    assert all(row["guard_name"] == "byte_pinned_function_library" for row in bootstrap_loads)
    installer = (ROOT / "INSTALL_CANONICAL_PORTABLE.ps1").read_text(encoding="utf-8")
    assert (
        installer.index("$BootstrapIntegrityFunctions = Join-Path $PSScriptRoot 'tools\\bootstrap_integrity.ps1'")
        < installer.index(". $BootstrapIntegrityFunctions")
        < installer.index("$sharedLeaf = Get-BootstrapSharedPortableLeaf $PSScriptRoot")
        < installer.index(". $sharedLeaf")
        < installer.index("$sourceManifest = Manifest")
        < installer.index("$BootstrapIntegrityFunctions = Join-Path $source 'tools\\bootstrap_integrity.ps1'")
        < installer.rindex(". $BootstrapIntegrityFunctions")
        < installer.index("[void](Assert-BootstrapIntegrityRecord $install)")
        < installer.index("[void](Start-ContainerWriterFence")
    )
    raster_write = next(
        row
        for row in payload["closure_direct_mutation_functions"]
        if row["node"] == "kmtech_shared.raster.RasterImage.save_png"
    )
    assert raster_write["decorated_source"] == ""
    assert raster_write["direct_callers"] == ["phs_label_workflow._save_raster_png"]
    assert raster_write["caller_guard_sources"] == ["phs_raster_png"]
    assert raster_write["coverage_status"] == "covered"
    trusted_nodes = [
        row["node"]
        for row in payload["closure_direct_mutation_functions"]
        if row["coverage_status"] == "trusted_control_plane"
    ]
    assert trusted_nodes == []
    assert payload["trusted_control_plane_mutations"] == []

    scheduled = payload["powershell_scheduled_task_guards"]["mutation_sites"]
    assert scheduled and all(row["guarded"] for row in scheduled)
    assert {row["file"] for row in scheduled} == {"tools/container_writer_fence.ps1"}
    assert {row["wrapper_function"] for row in scheduled} <= {
        "Disable-ContainerScheduledTaskUnderWriterFence",
        "Enable-ContainerScheduledTaskUnderWriterFence",
        "Stop-ContainerScheduledTaskUnderWriterFence",
        "DisableAndStop-ContainerScheduledTaskUnderWriterFence",
        "Remove-ContainerScheduledTaskUnderWriterFence",
    }

    lexical_sink = next(
        row
        for row in payload["writer_sinks"]
        if row["function"] == "event_log_store._interprocess_file_lock"
    )
    assert lexical_sink["marker_kind"] == "writer_admission"
    assert lexical_sink["source"] == "event_interprocess_lock"

    route_ids = {route["route_id"] for route in payload["known_route_coverage"]}
    assert route_ids == {
        "canonical_installer",
        "event",
        "gui_startup",
        "persistent_relay",
        "raw_runner",
    }
    python_routes = [
        route for route in payload["known_route_coverage"] if route["kind"] == "python"
    ]
    assert all(route["start_present"] is True for route in python_routes)
    assert all(route["reachable_direct_mutation_functions"] for route in python_routes)

    gui_startup = next(
        route
        for route in payload["known_route_coverage"]
        if route["route_id"] == "gui_startup"
    )
    assert gui_startup["pass"] is True
    assert gui_startup["unfenced_direct_mutation_functions"] == []

    event_route = next(
        route for route in payload["known_route_coverage"] if route["route_id"] == "event"
    )
    assert event_route["pass"] is True
    assert event_route["unfenced_direct_mutation_functions"] == []

    relay_route = next(
        route
        for route in payload["known_route_coverage"]
        if route["route_id"] == "persistent_relay"
    )
    assert relay_route["pass"] is True
    assert relay_route["unfenced_direct_mutation_functions"] == []
    assert relay_route["reachable_direct_mutation_functions"]

    raw_runner = next(
        route
        for route in payload["known_route_coverage"]
        if route["route_id"] == "raw_runner"
    )
    assert raw_runner["pass"] is True
    assert raw_runner["unfenced_direct_mutation_functions"] == []

    installer = next(
        route
        for route in payload["known_route_coverage"]
        if route["route_id"] == "canonical_installer"
    )
    assert installer["pass"] is True
    assert installer["unknown_delegated_sources"] == []
    assert installer["scheduled_task_guard_failures"] == []
    assert {
        "tools/direct_sync_relay_operator.py",
        "tools/direct_sync_relay_install_pack.py",
        "tools/active_work_probe.py",
        "tools/install_protected_admin.py",
    } <= set(payload["entrypoint_modules"])


def test_container_writer_sink_inventory_cli_is_read_only_without_write(
    tmp_path, capsys
) -> None:
    module = _load_module()
    payload = module.derive_inventory(ROOT)
    encoded = module._canonical_json_bytes(payload)
    snapshot_path = tmp_path / "inventory.json"
    snapshot_path.write_text("stale\n", encoding="utf-8")
    before = snapshot_path.read_bytes()
    module.SNAPSHOT_PATH = snapshot_path

    assert module.main([]) == 0
    assert snapshot_path.read_bytes() == before
    capsys.readouterr()

    try:
        module.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("--help should exit through argparse")
    assert snapshot_path.read_bytes() == before
    capsys.readouterr()

    snapshot_path.write_bytes(encoded)
    assert module.main(["--check"]) == 0
    assert snapshot_path.read_bytes() == encoded
    capsys.readouterr()

    snapshot_path.write_text("stale\n", encoding="utf-8")
    assert module.main(["--write"]) == 0
    assert snapshot_path.read_bytes() == encoded


def test_raw_scheduled_task_mutation_outside_approved_wrapper_fails_closed(
    tmp_path: Path,
) -> None:
    module = _load_module()
    for relative in module.POWERSHELL_PATHS:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# no mutation\n", encoding="utf-8")
    (tmp_path / "INSTALL_CANONICAL_PORTABLE.ps1").write_text(
        "function Invoke-Bad {\n  disable-scheduledtask -TaskName x\n}\n",
        encoding="utf-8",
    )
    inventory = module._collect_powershell_inventory(tmp_path)
    failures = [row for row in inventory["mutation_sites"] if not row["guarded"]]
    assert len(failures) == 1
    assert failures[0]["file"] == "INSTALL_CANONICAL_PORTABLE.ps1"
    assert failures[0]["command"] == "Disable-ScheduledTask"


def _write_minimal_inventory_fixture(root: Path, container_source: str) -> None:
    entrypoint_sources = {
        "portable/main.py": "def main():\n    pass\n",
        "Container_Audit.py": container_source,
        "container_audit_product_host.py": "def dispatch_product_mode():\n    pass\n",
        "user_relay.py": "def main():\n    pass\n",
        "direct_sync_auto_bootstrap.py": (
            "def run_direct_sync_auto_bootstrap():\n    pass\n"
        ),
        "tools/direct_sync_relay_runner.py": "def main():\n    pass\n",
    }
    for relative, source in entrypoint_sources.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    (root / "writer_session_fence.py").write_text(
        "def writer_sink(source):\n"
        "    def decorate(function):\n"
        "        return function\n"
        "    return decorate\n",
        encoding="utf-8",
    )
    module = _load_module()
    for relative in module.POWERSHELL_PATHS:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# no scheduled-task mutation\n", encoding="utf-8")


@pytest.mark.parametrize("mutation", ["remove_guard", "bypass_facade"])
def test_shared_runtime_sql_requires_exact_guarded_facade_callers(tmp_path, mutation):
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "import producer_runtime_client\ndef main():\n    pass\n")
    for relative in ("producer_runtime_client.py", "direct_sync_push.py", "kmtech_shared/runtime.py"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    (tmp_path / "kmtech_shared/__init__.py").write_bytes((ROOT / "kmtech_shared/__init__.py").read_bytes())
    before = module.derive_inventory(tmp_path)
    runtime_rows = [row for row in before["closure_direct_mutation_functions"]
                    if row["file"] == "kmtech_shared/runtime.py"]
    assert len(runtime_rows) == 7
    assert all(row["coverage_status"] == "covered" for row in runtime_rows)
    assert not any(row["target"].startswith("kmtech_shared.runtime.")
                   for row in before["caller_fence_reference_failures"])
    facade = tmp_path / "producer_runtime_client.py"
    source = facade.read_text(encoding="utf-8")
    if mutation == "remove_guard":
        original = '@writer_sink("producer_runtime_storage")\ndef init_runtime_schema'
        assert original in source
        source = source.replace(original, "def init_runtime_schema", 1)
    else:
        source += "\ndef bypass(conn):\n    _shared_runtime.init_runtime_schema(conn)\n"
    facade.write_text(source, encoding="utf-8")
    rejected = module.derive_inventory(tmp_path)
    assert "kmtech_shared.runtime.init_runtime_schema" in {
        row["node"] for row in rejected["uncovered_direct_mutation_functions"]
    }
    if mutation == "bypass_facade":
        assert "kmtech_shared.runtime.init_runtime_schema" in {
            row["target"] for row in rejected["caller_fence_reference_failures"]
        }


def test_new_shipped_powershell_helper_requires_a_registered_guard(
    tmp_path: Path,
) -> None:
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    pass\n")
    new_helper = Path("tools/new-placement-helper.ps1")
    helper_path = tmp_path / new_helper
    helper_path.write_text(
        "Remove-Item -LiteralPath 'fixture' -Force\n",
        encoding="utf-8",
    )
    assets = tuple((path.as_posix(), path.as_posix()) for path in module.POWERSHELL_PATHS)
    assets += ((new_helper.as_posix(), new_helper.as_posix()),)
    builder = tmp_path / "tools" / "build_portable_release_candidate.py"
    builder.write_text(
        "PORTABLE_INSTALL_ASSETS = " + repr(assets) + "\n",
        encoding="utf-8",
    )

    payload = module.derive_inventory(tmp_path)

    assert new_helper.as_posix() in payload["powershell_execution_inventory"][
        "asset_paths"
    ]
    assert any(
        row["file"] == new_helper.as_posix()
        and row["kind"] == "script_entrypoint"
        for row in payload["powershell_guard_failures"]
    )


def test_direct_mutation_before_registered_helper_guard_fails_closed(
    tmp_path: Path,
) -> None:
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    pass\n")
    helper = tmp_path / "INSTALL_THIS_PC.ps1"
    helper.write_text(
        "Remove-Item -LiteralPath 'fixture' -Force\n"
        + _fenced_powershell_fixture(""),
        encoding="utf-8",
    )

    payload = module.derive_inventory(tmp_path)

    assert any(
        row["file"] == "INSTALL_THIS_PC.ps1"
        and row["kind"] == "filesystem_mutation"
        and row["line"] == 1
        for row in payload["powershell_guard_failures"]
    )


def test_new_direct_writer_sink_without_real_fence_fails_inventory_gate(
    tmp_path: Path,
) -> None:
    module = _load_module()
    unfenced = (
        "from pathlib import Path\n"
        "def new_sink(path: Path):\n"
        "    path.write_text('mutation', encoding='utf-8')\n"
        "def main():\n"
        "    result = new_sink(Path('effect.txt'))\n"
    )
    _write_minimal_inventory_fixture(tmp_path, unfenced)
    payload = module.derive_inventory(tmp_path)
    assert [row["node"] for row in payload["uncovered_direct_mutation_functions"]] == [
        "Container_Audit.new_sink"
    ]
    gui_route = next(
        row
        for row in payload["known_route_coverage"]
        if row["route_id"] == "gui_startup"
    )
    assert gui_route["pass"] is False
    assert gui_route["unfenced_direct_mutation_functions"] == [
        "Container_Audit.new_sink"
    ]

    fake_decorator = (
        "from pathlib import Path\n"
        "def writer_sink(source):\n"
        "    return lambda function: function\n"
        "@writer_sink('fake')\n"
        "def new_sink(path: Path):\n"
        "    path.write_text('mutation', encoding='utf-8')\n"
        "def main():\n"
        "    result = new_sink(Path('effect.txt'))\n"
    )
    (tmp_path / "Container_Audit.py").write_text(fake_decorator, encoding="utf-8")
    spoofed = module.derive_inventory(tmp_path)
    assert [row["node"] for row in spoofed["uncovered_direct_mutation_functions"]] == [
        "Container_Audit.new_sink"
    ]

    fenced = (
        "from pathlib import Path\n"
        "from writer_session_fence import writer_sink\n"
        "@writer_sink('fixture_sink')\n"
        "def new_sink(path: Path):\n"
        "    path.write_text('mutation', encoding='utf-8')\n"
        "def main():\n"
        "    result = new_sink(Path('effect.txt'))\n"
    )
    (tmp_path / "Container_Audit.py").write_text(fenced, encoding="utf-8")
    admitted = module.derive_inventory(tmp_path)
    assert admitted["uncovered_direct_mutation_functions"] == []
    assert admitted["writer_sink_sources"] == ["fixture_sink"]
    gui_route = next(
        row
        for row in admitted["known_route_coverage"]
        if row["route_id"] == "gui_startup"
    )
    assert gui_route["pass"] is True


def test_unimported_shipped_package_writer_cannot_escape_inventory(
    tmp_path: Path,
) -> None:
    module = _load_module()
    _write_minimal_inventory_fixture(
        tmp_path,
        "def main():\n    pass\n",
    )
    candidate = (
        tmp_path
        / "kmtech_factory_contracts"
        / "new_unimported_writer.py"
    )
    candidate.parent.mkdir(parents=True)
    candidate.write_text(
        "from pathlib import Path\n"
        "def persist(path: Path):\n"
        "    path.write_text('mutation', encoding='utf-8')\n",
        encoding="utf-8",
    )

    payload = module.derive_inventory(tmp_path)
    assert "kmtech_factory_contracts/new_unimported_writer.py" in payload[
        "entrypoint_modules"
    ]
    assert [row["node"] for row in payload["uncovered_direct_mutation_functions"]] == [
        "kmtech_factory_contracts.new_unimported_writer.persist"
    ]

    candidate.write_text(
        "from pathlib import Path\n"
        "from writer_session_fence import writer_sink\n"
        "@writer_sink('new_unimported_writer')\n"
        "def persist(path: Path):\n"
        "    path.write_text('mutation', encoding='utf-8')\n",
        encoding="utf-8",
    )
    admitted = module.derive_inventory(tmp_path)
    assert admitted["uncovered_direct_mutation_functions"] == []
    assert "new_unimported_writer" in admitted["writer_sink_sources"]


def test_new_network_writer_without_fence_fails_inventory_gate(
    tmp_path: Path,
) -> None:
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    pass\n")
    candidate = tmp_path / "new_network_writer.py"
    candidate.write_text(
        "def transmit(session):\n"
        "    return session.post('https://producer.invalid/events')\n",
        encoding="utf-8",
    )
    payload = module.derive_inventory(tmp_path)
    assert [row["node"] for row in payload["uncovered_direct_mutation_functions"]] == [
        "new_network_writer.transmit"
    ]
    assert payload["uncovered_direct_mutation_functions"][0]["mutation_sites"] == [
        {
            "line": 2,
            "operation": "session.post",
            "category": "network",
            "writer_admission_sources": [],
        }
    ]


def test_new_external_task_or_service_registration_without_fence_fails_inventory_gate(
    tmp_path: Path,
) -> None:
    module = _load_module()
    unfenced = (
        "import subprocess\n"
        "def install_scheduled_task():\n"
        "    subprocess.run(['powershell.exe', '-Command', "
        "'Register-ScheduledTask -TaskName fixture -Force'])\n"
        "def install_service():\n"
        "    command = ['sc.exe', 'create', 'fixture', 'binPath=fixture.exe']\n"
        "    subprocess.run(command, check=False)\n"
        "def main():\n"
        "    install_scheduled_task()\n"
        "    install_service()\n"
    )
    _write_minimal_inventory_fixture(tmp_path, unfenced)

    payload = module.derive_inventory(tmp_path)

    assert [row["node"] for row in payload["uncovered_direct_mutation_functions"]] == [
        "Container_Audit.install_scheduled_task",
        "Container_Audit.install_service",
    ]
    assert all(
        row["mutation_sites"][0]["category"] == "external_process"
        for row in payload["uncovered_direct_mutation_functions"]
    )
    assert {"Register-ScheduledTask", "sc.exe"} <= set(
        payload["python_external_control_commands"]["commands"]
    )

    fenced = (
        "import subprocess\n"
        "from writer_session_fence import writer_sink\n"
        "@writer_sink('external_control_fixture')\n"
        "def install_scheduled_task():\n"
        "    subprocess.run(['powershell.exe', '-Command', "
        "'Register-ScheduledTask -TaskName fixture -Force'])\n"
        "@writer_sink('external_control_fixture')\n"
        "def install_service():\n"
        "    subprocess.run(['sc.exe', 'create', 'fixture', 'binPath=fixture.exe'])\n"
        "def main():\n"
        "    install_scheduled_task()\n"
        "    install_service()\n"
    )
    (tmp_path / "Container_Audit.py").write_text(fenced, encoding="utf-8")
    admitted = module.derive_inventory(tmp_path)
    assert admitted["uncovered_direct_mutation_functions"] == []


def test_external_control_builder_and_aliased_runner_require_fence_at_execution(
    tmp_path: Path,
) -> None:
    module = _load_module()
    unfenced = (
        "from subprocess import run as launch\n"
        "def scheduled_task_command():\n"
        "    return ['schtasks', '/Create', '/TN', 'fixture', '/TR', 'fixture.exe']\n"
        "def service_command():\n"
        "    return ['sc.exe', 'create', 'fixture', 'binPath=fixture.exe']\n"
        "def run_control_command(command):\n"
        "    launch(command, check=False)\n"
        "def main():\n"
        "    run_control_command(scheduled_task_command())\n"
        "    run_control_command(service_command())\n"
    )
    _write_minimal_inventory_fixture(tmp_path, unfenced)

    payload = module.derive_inventory(tmp_path)

    assert [row["node"] for row in payload["uncovered_direct_mutation_functions"]] == [
        "Container_Audit.run_control_command"
    ]
    mutation_site = payload["uncovered_direct_mutation_functions"][0][
        "mutation_sites"
    ][0]
    assert mutation_site["operation"] == "subprocess.run"
    assert mutation_site["category"] == "external_process"
    assert {"schtasks", "sc.exe"} <= set(
        payload["python_external_control_commands"]["commands"]
    )

    fenced = unfenced.replace(
        "from subprocess import run as launch\n",
        "from subprocess import run as launch\n"
        "from writer_session_fence import writer_sink\n",
    ).replace(
        "def run_control_command(command):\n",
        "@writer_sink('external_control_fixture')\n"
        "def run_control_command(command):\n",
    )
    (tmp_path / "Container_Audit.py").write_text(fenced, encoding="utf-8")
    admitted = module.derive_inventory(tmp_path)
    assert admitted["uncovered_direct_mutation_functions"] == []


POWERSHELL_UNFENCED_INJECTIONS = (
    pytest.param(
        "script_entrypoint",
        "Remove-Item -LiteralPath 'fixture' -Force\n",
        "script_entrypoint",
        id="direct-helper",
    ),
    pytest.param(
        "dot_source",
        ". $PSScriptRoot\\fixture-unfenced.ps1\n",
        "dot_source",
        id="dot-source",
    ),
    pytest.param(
        "module_import",
        "Import-Module 'fixture-unfenced.psm1'\n",
        "dot_source",
        id="module-import",
    ),
    pytest.param(
        "start_process",
        "Start-Process -FilePath 'schtasks.exe' -ArgumentList '/Create'\n",
        "start_process",
        id="start-process",
    ),
    pytest.param(
        "invoke_item",
        "Invoke-Item 'fixture-unfenced.cmd'\n",
        "start_process",
        id="invoke-item",
    ),
    pytest.param(
        "invoke_expression",
        "Invoke-Expression $runtimeCommand\n",
        "invoke_expression",
        id="invoke-expression",
    ),
    pytest.param(
        "call_operator",
        "& $runtimeCommand '/Create'\n",
        "call_operator",
        id="call-operator",
    ),
    pytest.param(
        "native_command",
        "powershell.exe -NoProfile -File .\\fixture-unfenced.ps1\n",
        "native_command",
        id="native-command",
    ),
    pytest.param(
        "relative_script_command",
        ".\\fixture-unfenced.ps1\n",
        "native_command",
        id="relative-script-command",
    ),
    pytest.param(
        "com_wmi_process_create",
        "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = 'cmd.exe /c exit 0' }\n",
        "com_wmi_process_create",
        id="com-wmi-process",
    ),
    pytest.param(
        "generic_com",
        "$automation = New-Object -ComObject 'MMC20.Application'\n",
        "com_wmi_process_create",
        id="generic-com",
    ),
    pytest.param(
        "dotnet_process_start",
        "[System.Diagnostics.Process]::Start('cmd.exe')\n",
        "dotnet_process_start",
        id="dotnet-process-start",
    ),
    pytest.param(
        "native_process_api",
        "[NativeMethods]::CreateProcessW($null, $commandLine)\n",
        "native_process_api",
        id="native-process-api",
    ),
    pytest.param(
        "scheduler_com",
        "$scheduler = New-Object -ComObject 'Schedule.Service'\n",
        "scheduler_com",
        id="scheduler-com",
    ),
    pytest.param(
        "service_control_api",
        "New-Service -Name fixture -BinaryPathName 'fixture.exe'\n",
        "service_control_api",
        id="service-control",
    ),
    pytest.param(
        "reflective_invocation",
        "$method = [Type]::GetType($typeName).GetMethod($methodName); $method.Invoke($null, @())\n",
        "reflective_invocation",
        id="reflective-invocation",
    ),
    pytest.param(
        "runspace_begin_invoke",
        "$pipeline.BeginInvoke()\n",
        "reflective_invocation",
        id="runspace-begin-invoke",
    ),
)


def _fenced_powershell_fixture(injected_line: str) -> str:
    return (
        "function Enter-ContainerPlacementWriterFence {\n"
        "    $probe = Enter-ContainerWriterDelegatedOperation -Source canonical_code_placement\n"
        "    Invoke-SelfElevated\n"
        "    return Enter-ContainerWriterDelegatedOperation -Source canonical_code_placement\n"
        "}\n"
        "$lease = Enter-ContainerPlacementWriterFence\n"
        "try {\n"
        + injected_line
        + "}\n"
        "finally {\n"
        "    Exit-ContainerWriterAdmission $lease\n"
        "}\n"
    )


def _run_inventory_release_gate(
    root: Path,
    payload: dict,
) -> subprocess.CompletedProcess[str]:
    snapshot = root / "tools" / "container_writer_sink_inventory.json"
    module = _load_module()
    snapshot.write_bytes(module._canonical_json_bytes(payload))
    return subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import pathlib,sys; "
                "from tools.build_portable_release_candidate import "
                "_assert_writer_sink_inventory; "
                "_assert_writer_sink_inventory(pathlib.Path(sys.argv[1]))"
            ),
            str(root),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    ("case_name", "injected_line", "expected_failure_kind"),
    POWERSHELL_UNFENCED_INJECTIONS,
)
def test_each_static_powershell_execution_form_breaks_release_gate_when_unfenced(
    tmp_path: Path,
    case_name: str,
    injected_line: str,
    expected_failure_kind: str,
) -> None:
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    pass\n")
    helper = tmp_path / "INSTALL_THIS_PC.ps1"
    helper.write_text(injected_line, encoding="utf-8")

    rejected = module.derive_inventory(tmp_path)
    failure_kinds = {
        row["kind"] for row in rejected["powershell_guard_failures"]
    }
    assert expected_failure_kind in failure_kinds, case_name
    gate = _run_inventory_release_gate(tmp_path, rejected)
    assert gate.returncode == 1, (case_name, gate.stdout, gate.stderr)
    assert "writer sink inventory is not release-admissible" in gate.stderr

    helper.write_text(_fenced_powershell_fixture(injected_line), encoding="utf-8")
    admitted = module.derive_inventory(tmp_path)
    assert admitted["powershell_guard_failures"] == [], case_name
    print(
        "INJECTION_GATE "
        f"case={case_name} kind={expected_failure_kind} "
        f"gate_exit={gate.returncode} reverted_guard_failures=0"
    )


def test_powershell_mutation_function_called_before_guard_fails_release_gate(
    tmp_path: Path,
) -> None:
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    pass\n")
    helper = tmp_path / "INSTALL_THIS_PC.ps1"
    helper.write_text(
        "function Invoke-EarlyWriter {\n"
        "    Remove-Item -LiteralPath 'fixture' -Force\n"
        "}\n"
        "Invoke-EarlyWriter\n"
        + _fenced_powershell_fixture(""),
        encoding="utf-8",
    )

    rejected = module.derive_inventory(tmp_path)
    assert any(
        row["function"] == "Invoke-EarlyWriter"
        and row["kind"] == "filesystem_mutation"
        for row in rejected["powershell_guard_failures"]
    )
    gate = _run_inventory_release_gate(tmp_path, rejected)
    assert gate.returncode == 1, (gate.stdout, gate.stderr)
    assert "writer sink inventory is not release-admissible" in gate.stderr
    print(f"EARLY_FUNCTION_GATE gate_exit={gate.returncode}")


def test_powershell_post_release_mutation_fails_release_gate(
    tmp_path: Path,
) -> None:
    module = _load_module()
    _write_minimal_inventory_fixture(tmp_path, "def main():\n    pass\n")
    helper = tmp_path / "INSTALL_THIS_PC.ps1"
    helper.write_text(
        _fenced_powershell_fixture("")
        + "Remove-Item -LiteralPath 'post-release-fixture' -Force\n",
        encoding="utf-8",
    )

    rejected = module.derive_inventory(tmp_path)
    release_line = next(
        entry["entry_guard"]["release_line"]
        for entry in rejected["powershell_execution_inventory"]["files"]
        if entry["file"] == "INSTALL_THIS_PC.ps1"
    )
    assert any(
        row["function"] == ""
        and row["kind"] == "filesystem_mutation"
        and row["line"] > int(release_line)
        for row in rejected["powershell_guard_failures"]
    )
    gate = _run_inventory_release_gate(tmp_path, rejected)
    assert gate.returncode == 1, (gate.stdout, gate.stderr)
    assert "writer sink inventory is not release-admissible" in gate.stderr
    print(f"POST_RELEASE_GATE gate_exit={gate.returncode}")

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


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


def test_container_writer_sink_inventory_has_expected_current_findings() -> None:
    payload = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    module = _load_module()

    assert payload["schema_version"] == "container-audit-writer-sink-inventory-v5"
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
        "sink_function_count": len(payload["writer_sinks"]),
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
    assert "Container_Audit._write_update_download" in covered_nodes
    assert "direct_sync_auto_bootstrap._write_json" in covered_nodes
    assert "event_log_store._interprocess_file_lock" in covered_nodes
    assert "event_log_store._append_event_log_entry_unlocked" in covered_nodes
    assert "transfer_seal.TransferSealStore._initialize" in covered_nodes
    assert "kmtech_factory_contracts.active_work_probe.cli._create_new_fsynced" in covered_nodes
    assert "tools.direct_sync_relay_operator._write_json_atomic" in covered_nodes
    raster_write = next(
        row
        for row in payload["closure_direct_mutation_functions"]
        if row["node"] == "vendor.kmtech_zero_pe.raster.RasterImage.save_png"
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

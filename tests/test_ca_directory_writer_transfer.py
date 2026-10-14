"""Directory preparation retains the b82 classifications without new admission."""
import ast
from collections import Counter
from copy import deepcopy
from pathlib import Path
import json
import subprocess

import pytest

from tools import derive_container_writer_sinks as inventory

ROOT = Path(__file__).resolve().parents[1]
BASE = "b82a74ce05a11d31632ee03314f82f4a50f52445"


@pytest.fixture(scope="module")
def closure():
    index = inventory._build_module_index(ROOT)
    paths = inventory._discover_shipped_application_paths(ROOT)
    return inventory._collect_import_closure(
        root=ROOT, entrypoint_modules=tuple(inventory._module_name(path) for path in paths),
        module_index=index,
    )


def _analyze(closure, change=None):
    parsed, edges = closure
    parsed = {name: {"path": item["path"], "tree": item["tree"]} for name, item in parsed.items()}
    if change:
        name, mutate = change
        parsed[name]["tree"] = deepcopy(parsed[name]["tree"])
        mutate(parsed[name]["tree"])
    analysis, graph, sources, markers = inventory._analyze_closure(
        parsed_modules=parsed, import_graph=edges, shell_kit_delegated=True,
    )
    return parsed, analysis, graph, sources, markers


def _function(tree, name):
    return next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)


def test_all_33_replaced_mkdir_sites_retain_the_old_argument_and_classification(closure):
    parsed, analysis, *_ = _analyze(closure)
    rows = analysis[inventory.DIRECTORY_PREPARATION_HELPER]["directory_preparation_forwarding"]
    assert len(rows) == len(inventory.DIRECTORY_PREPARATION_CALLS) == 33
    assert Counter(row["classification"] for row in rows) == {
        "decorator": 25, "writer_admission": 5, "probe_only": 2,
        "pre_admission_directory_preparation": 1,
    }
    expected = set(inventory.DIRECTORY_PREPARATION_CALLS)
    matched = set()
    for module in sorted({caller.rsplit(".", 1)[0] for caller, _ in expected}):
        # The class method belongs to the Container_Audit module.
        module = "Container_Audit" if module == "Container_Audit.ContainerAudit" else module
        path = parsed[module]["path"].as_posix()
        result = subprocess.run(["git", "show", f"{BASE}:{path}"], cwd=ROOT,
                                capture_output=True, check=True,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        collector = inventory.FunctionCollector(module_name=module)
        collector.visit(ast.parse(result.stdout.decode("utf-8")))
        for caller, info in collector.functions.items():
            for call in ast.walk(info["node"]):
                if not isinstance(call, ast.Call):
                    continue
                directory = None
                if isinstance(call.func, ast.Attribute) and call.func.attr == "mkdir":
                    directory = call.func.value
                elif isinstance(call.func, ast.Attribute) and call.func.attr == "makedirs" and call.args:
                    directory = call.args[0]
                if directory is not None:
                    key = (caller, inventory._ast_sha256(directory))
                    if key in expected:
                        assert key not in matched
                        matched.add(key)
    assert matched == expected
    old_inventory = json.loads(subprocess.run(
        ["git", "show", f"{BASE}:tools/container_writer_sink_inventory.json"], cwd=ROOT,
        capture_output=True, check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout)
    current_inventory = json.loads((ROOT / "tools/container_writer_sink_inventory.json").read_bytes())
    assert current_inventory["writer_sink_sources"] == old_inventory["writer_sink_sources"]


@pytest.mark.parametrize("drift", ["body", "caller", "argument", "admission", "probe", "callback"])
def test_preparation_transfer_rejects_new_effects_or_permission_drift(closure, drift):
    module = "storage_policy"
    def change(tree):
        if drift == "body":
            _function(tree, "ensure_user_runtime_directory").body.append(ast.parse("path.write_text('')").body[0])
        elif drift == "caller":
            tree.body.extend(ast.parse("def unregistered(path):\n    ensure_user_runtime_directory(path)\n").body)
        elif drift == "callback":
            tree.body.extend(ast.parse("alias = ensure_user_runtime_directory").body)
        elif drift == "argument":
            fn = _function(tree, "ensure_container_audit_storage_dirs")
            call = next(n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                        and n.func.id == "ensure_user_runtime_directory")
            call.args[0] = ast.Name(id="different_directory", ctx=ast.Load())
        elif drift == "admission":
            fn = _function(tree, "main")
            for node in ast.walk(fn):
                if isinstance(node, ast.With):
                    for item in node.items:
                        if isinstance(item.context_expr, ast.Call) and isinstance(item.context_expr.func, ast.Name) and item.context_expr.func.id == "writer_admission":
                            item.context_expr.func.id = "unfenced_context"
        else:
            fn = _function(tree, "_prepare_status_temp")
            for decorator in fn.decorator_list:
                if isinstance(decorator, ast.Call):
                    for keyword in decorator.keywords:
                        if keyword.arg == "probe_only":
                            keyword.value = ast.Constant(value=False)
    if drift == "admission":
        module = "user_relay"
    elif drift == "probe":
        module = "direct_sync_push"
    with pytest.raises(inventory.InventoryError, match="directory preparation"):
        _analyze(closure, (module, change))


def test_prebootstrap_directory_classification_does_not_exempt_business_file_writes(closure):
    def change(tree):
        _function(tree, "ensure_container_audit_storage_dirs").body.extend(
            ast.parse("Path('business-file').write_text('')").body)
    parsed, analysis, graph, sources, _ = _analyze(closure, ("storage_policy", change))
    coverage, predecessor = inventory._coverage_states(
        starts=inventory._normalize_start_names(graph), call_graph=graph, sink_nodes=set(sources))
    rows = inventory._closure_mutation_rows(parsed_modules=parsed, node_analysis=analysis,
        coverage=coverage, predecessor=predecessor, sink_sources=sources, call_graph=graph)
    prep = next(row for row in rows if row["node"] == "storage_policy.ensure_container_audit_storage_dirs")
    assert prep["coverage_status"] == "uncovered"


def test_directory_preparation_remains_usable_before_writer_bootstrap(tmp_path, monkeypatch):
    import storage_policy
    import writer_session_fence
    def unexpected_admission(*args, **kwargs):
        pytest.fail("directory preparation introduced writer admission")
    monkeypatch.setattr(writer_session_fence, "writer_admission", unexpected_admission)
    directory = tmp_path / "user" / "new-runtime"
    storage_policy.ensure_user_runtime_directory(directory, environ={"PROGRAMDATA": str(tmp_path / "machine")})
    assert directory.is_dir()

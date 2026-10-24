"""The inventory exempts one read-only edge, preserving mutation detection."""
import ast
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def classify(change):
    spec = importlib.util.spec_from_file_location(
        "observe_inventory", ROOT / "tools/derive_container_writer_sinks.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = ast.parse((ROOT / "auto_update.py").read_bytes())
    names = {"fixed_helper", "_run_fixed_helper", "process_snapshot"}
    functions = [deepcopy(node) for node in original.body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    tree = ast.parse("import json\nfrom writer_session_fence import writer_sink\n")
    tree.body.extend(functions)
    snapshot = next(node for node in functions if node.name == "process_snapshot")
    raw = next(node for node in functions if node.name == "_run_fixed_helper")
    call = snapshot.body[0].value.args[0]
    trees = {"auto_update": tree}
    if change == "variable":
        call.args[1] = ast.Name(id="mode", ctx=ast.Load())
    elif change in {"Apply", "Verify"}:
        call.args[1] = ast.Constant(value=change)
    elif change == "caller":
        snapshot.name = "other_snapshot"
    elif change == "module":
        tree.body.remove(snapshot)
        other = ast.parse("import json\nfrom auto_update import _run_fixed_helper\n")
        other.body.append(snapshot)
        trees["other_module"] = other
    elif change == "body":
        raw.body.append(ast.parse("subprocess.run(['another-helper'])").body[0])
    elif change == "position":
        snapshot.body.insert(0, ast.parse("unrelated = True").body[0])
    elif change == "extra_reference":
        snapshot.body.append(ast.parse('_run_fixed_helper(control, "Apply")').body[0])
    elif change == "unfenced":
        next(n for n in functions if n.name == "fixed_helper").decorator_list = []
    elif change != "exact":
        raise AssertionError("unknown scene")
    parsed, analysis, sources = {}, {}, {}
    for name, value in trees.items():
        collector = module.FunctionCollector(module_name=name)
        collector.visit(value)
        parsed[name] = {"path": Path(name + ".py"), "tree": value,
                        "collector": collector}
    known = {name for payload in parsed.values() for name in payload["collector"].functions}
    for payload in parsed.values():
        for name, info in payload["collector"].functions.items():
            visitor = module._NodeVisitor(collector=payload["collector"], current_qualname=name,
                current_class=info["class_qualname"], known_nodes=known,
                initial_import_scope=name.rsplit(".", 1)[0])
            for statement in info["node"].body:
                visitor.visit(statement)
            analysis[name] = {"calls": sorted(visitor.calls), "mutation_sites": visitor.mutation_sites}
            if info["decorator_sources"]:
                sources[name] = info["decorator_sources"][0]
    graph = {name: row["calls"] for name, row in analysis.items()}
    rows = module._closure_mutation_rows(parsed_modules=parsed, node_analysis=analysis,
        coverage={"auto_update._run_fixed_helper": {"unsunk_entrypoints": {"reader"}}},
        predecessor={}, sink_sources=sources, call_graph=graph)
    return next(row for row in rows if row["node"] == "auto_update._run_fixed_helper")


def test_exact_literal_observe_edge_is_read_only_with_original_fenced_helper():
    row = classify("exact")
    assert row["coverage_status"] == "covered"
    assert row["caller_guard_sources"] == ["auto_update_control"]
    assert row["direct_callers"] == ["auto_update.fixed_helper", "auto_update.process_snapshot"]
    assert row["unsunk_entrypoints"] == []


@pytest.mark.parametrize("change", ["variable", "Apply", "Verify", "caller", "module",
                                   "body", "position", "extra_reference", "unfenced"])
def test_other_modes_callers_modules_or_execution_bodies_remain_uncovered(change):
    row = classify(change)
    assert row["coverage_status"] == "uncovered"
    assert row["caller_guard_sources"] == []
    assert row["unsunk_entrypoints"] == ["reader"]

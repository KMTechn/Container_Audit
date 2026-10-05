"""GUI startup must never give a console child the scanner's focus."""
import ast
from collections import Counter
from pathlib import Path
import subprocess

import pytest


@pytest.mark.parametrize("command", ["rev-parse", "status"])
def test_source_generation_git_launch_is_hidden(tmp_path, monkeypatch, command):
    import data_generation_guard as guard
    from tools import register_container_audit_worker_pc as registrar

    code = tmp_path / "code"
    code.mkdir()
    (code / "Container_Audit.py").write_text('CURRENT_VERSION = "v2.0.99"\n')
    monkeypatch.setattr(guard, "__file__", str(code / "data_generation_guard.py"))
    monkeypatch.setattr(registrar, "_current_user_sid", lambda: "S-1-5-21-353")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    calls = []

    def git(arguments, **options):
        calls.append((arguments, options))
        return "a" * 40 + "\n" if "rev-parse" in arguments else ""

    monkeypatch.setattr(guard.subprocess, "check_output", git)
    result = guard.record_before_data_open(tmp_path / "data")
    assert result["allowed"]
    assert [args[4] for args, _ in calls] == ["rev-parse", "status"]
    arguments, options = next(row for row in calls if command in row[0])
    assert arguments[:4] == ["git", "--no-optional-locks", "-C", str(code)]
    assert options["text"] is True and options["stderr"] == subprocess.DEVNULL
    assert not options.get("shell", False)
    assert options.get("creationflags", 0) & subprocess.CREATE_NO_WINDOW


# These existing console/qualification entry points are never dispatched by
# the GUI. Counts make the exceptions finite: a new call needs classification.
_CONSOLE_ONLY = Counter({
    ("kmtech_factory_contracts/build_cli.py", "_git"): 1,
    ("tools/capture_container_operator_ui.py", "_git_bytes"): 1,
    ("tools/capture_container_operator_ui.py", "_git_paths_match_commit"): 1,
    ("tools/direct_sync_relay_install_pack.py", "_python_runtime_import_report"): 1,
    ("tools/direct_sync_relay_install_pack.py", "_run_command"): 1,
    ("tools/install_logistics_runtime_profile.py", "_secure_profile_directory"): 1,
    ("tools/install_protected_admin.py", "_run_powershell"): 1,
    ("tools/manual_real_ui_walkthrough_capture.py", "main"): 1,
    ("tools/packaged_real_ui_driver.py", "launch"): 1,
    ("tools/read_release_qualification_tag.py", "_git"): 1,
    ("tools/run_repository_tests.py", "git"): 1,
    ("tools/run_repository_tests.py", "_repository_state"): 2,
    ("tools/run_repository_tests.py", "main"): 2,
    ("tools/run_test1_exact_artifact.py", "launch_exact_artifact"): 1,
})
_PRIMITIVES = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.startfile", "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
}
_FLAGS = {"CREATE_NO_WINDOW": 0x08000000, "DETACHED_PROCESS": 8,
          "CREATE_NEW_PROCESS_GROUP": 0x200, "CREATE_NEW_CONSOLE": 0x10}


def _flag_value(node, assignments):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Attribute):
        return _FLAGS.get(node.attr, 0)
    if isinstance(node, ast.Name) and node.id in assignments:
        return _flag_value(assignments[node.id], {})
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _flag_value(node.left, assignments) | _flag_value(node.right, assignments)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "getattr" and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)):
        return _FLAGS.get(node.args[1].value, 0)
    return 0


def test_product_process_inventory_has_no_unclassified_console_launch():
    root = Path(__file__).resolve().parents[1]
    paths = list(root.glob("*.py"))
    for directory in ("tools", "portable", "kmtech_factory_contracts", "kmtech_shared", "qualification"):
        paths.extend((root / directory).rglob("*.py"))
    exceptions, failures = Counter(), []
    for path in sorted(paths):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name] = item.name
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                    if default is not None and ast.unparse(default) in _PRIMITIVES:
                        aliases[argument.arg] = ast.unparse(default)
        functions = [node for node in ast.walk(tree)
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            raw = ast.unparse(node.func)
            first, *rest = raw.split(".")
            name = ".".join([aliases.get(first, first), *rest])
            if name not in _PRIMITIVES and not name.rsplit(".", 1)[-1].startswith(("CreateProcess", "ShellExecute")):
                continue
            owners = [f for f in functions if f.lineno <= node.lineno <= f.end_lineno]
            owner = min(owners, key=lambda f: f.end_lineno - f.lineno) if owners else tree
            identity = (path.relative_to(root).as_posix(), getattr(owner, "name", "<module>"))
            options = {option.arg: option.value for option in node.keywords}
            location = f"{identity[0]}:{node.lineno}"
            if "shell" in options and not (isinstance(options["shell"], ast.Constant) and options["shell"].value is False):
                failures.append(location + " shell launch")
            if identity in _CONSOLE_ONLY:
                exceptions[identity] += 1
                continue
            assignments = {target.id: item.value for item in ast.walk(owner)
                           if isinstance(item, ast.Assign) and item.lineno < node.lineno
                           for target in item.targets if isinstance(target, ast.Name)}
            flags = _flag_value(options.get("creationflags"), assignments)
            if not flags & _FLAGS["CREATE_NO_WINDOW"] or flags & _FLAGS["CREATE_NEW_CONSOLE"]:
                failures.append(location + " missing CREATE_NO_WINDOW")
    assert exceptions == _CONSOLE_ONLY
    assert not failures, "\n".join(failures)

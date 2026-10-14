"""Ordered reader/publication overlap, with real files only in isolated temp storage."""
import ast
import ctypes
import hashlib
import inspect
import json
import os
from pathlib import Path
import threading
import time

import pytest
import atomic_replace as publication

ROOT = Path(__file__).resolve().parents[1]
PINNED_EXCLUSIONS = {
    "kmtech_shared/data_generation.py": ("c3d6ecb693183afb9b93402bccd1eee64b7cfc26024b82bbc099a08accc97245", "바이트 고정 정본 — 정본 주인 후속"),
    "kmtech_shared/powershell/data_generation.ps1": ("b809e49985c73e0b1aedbe9dd3a8050177939f6fb088087e6d3e4c9bc05b5c96", "바이트 고정 정본 — 정본 주인 후속"),
    "kmtech_shared/raster.py": ("17c3d10498f9f5b845858861e671fff4715820b0e48719864d8dec4b9743f244", "바이트 고정 정본 — 정본 주인 후속"),
    "kmtech_shared/diagnostic_log.py": ("085c47ad7cf42130de74240a6e3dccefc2502d844591f775d46fedaabc6ad36b", "바이트 고정 정본 — 정본 주인 후속"),
    "shell/shell_fileio.py": ("d6a97d78927be4be7312105507a46adf26d1ad2520c86bd81139683403a68266", "바이트 고정 정본 — 정본 주인 후속"),
}
TEST_REPLACEMENT_DOUBLES = {
    ("tests/test_event_log_projection.py", "interleave"),
    ("tests/test_event_log_projection.py", "changed_stat"),
    ("tests/test_startup_check_report.py", "test_report_is_atomic_sanitized_and_never_acquires_admission"),
    ("tests/test_installation_launcher_transport.py", "test_limited_launcher_rejects_unpinned_or_reparse_transport"),
    ("tests/test_installation_launcher_transport.py", "test_preverification_fault_never_executes_source"),
}


MOVEMENT_EXCLUSIONS = {('INSTALL_THIS_PC.ps1', 'Restore-ContainerStartupUpdatePreimage', '01732e3a2f354425721a765af5d4acd15f194801276c8368ab46a04ff59819c8'): 'guarded quarantine or version directory move; no file publication', ('INSTALL_THIS_PC.ps1', 'Invoke-ContainerConvergentRemoval', 'bb0fcc5b04d60c75b98418b0386d81b785ccc86186b0f2bfd1215deabec33b38'): 'guarded quarantine or version directory move; no file publication', ('INSTALL_THIS_PC.ps1', '<module>', '8becac505a03d2f48be68878e420a1990318b3cbd009d15ae93200902bb2824b'): 'guarded quarantine or version directory move; no file publication', ('INSTALL_THIS_PC.ps1', '<module>', '929439eadd1356766f52333644e3ba6898bc71f60c2f58ef8eef8f7bb5f7121f'): 'guarded quarantine or version directory move; no file publication', ('INSTALL_THIS_PC.ps1', '<module>', 'a0898bfdf0d2b7414073c852daff544aeee76e3045a90b01f2bf714d090aa6cd'): 'guarded quarantine or version directory move; no file publication', ('INSTALL_THIS_PC.ps1', '<module>', '4ccfa4fb5b4b733240046536856ea650da76fc768e15ed7d925144a5d6ed2c87'): 'guarded quarantine or version directory move; no file publication', ('INSTALL_THIS_PC.ps1', '<module>', 'b5956526cc6d6a68b9a8c26c82f3a7b905b3fe9274ca0adf9ac06c26b5a52f0f'): 'guarded quarantine or version directory move; no file publication', ('INSTALL_THIS_PC.ps1', '<module>', '560e01bae1147700e870caa8f44ace81e6cccbc274539bd24cc1e62470a2c8ac'): 'guarded quarantine or version directory move; no file publication', ('tools/bootstrap_integrity.ps1', 'Invoke-BootstrapVerifiedReplacementRestore', '04f07000709349c4620ee0492bf5bb5b424b5a42d22c08eb8ed81a34cab2963c'): 'guarded quarantine or version directory move; no file publication', ('tools/bootstrap_integrity.ps1', 'Invoke-BootstrapVerifiedReplacementRestore', 'ba30833e116cc4a8c7a59819e551e8224b063cd4a0f341d438216a08c0681c42'): 'guarded quarantine or version directory move; no file publication', ('tools/bootstrap_integrity.ps1', 'Invoke-BootstrapVerifiedReplacementRestore', '347d6e1c77eea361c7bdeb27e6221c9f39f3ab9d4f824971f62abbe317b3e695'): 'guarded quarantine or version directory move; no file publication', ('tools/bootstrap_integrity.ps1', 'Invoke-BootstrapVerifiedReplacementRestore', '1f0294214766f50cf7e4ec91b12c1949c99c16f831a2908516040eb71dc92a5e'): 'guarded quarantine or version directory move; no file publication', ('tools/bootstrap_integrity.ps1', 'Invoke-BootstrapVerifiedReplacementRestore', '4439e03dbbad17adadfbf6f394a6b0a31c70403c39d143bb061c5b162d0971a0'): 'guarded quarantine or version directory move; no file publication'}


def _direct_replacements(root):
    """Scan owned source and named test doubles; exclude generated/dependency trees."""
    import re
    import warnings
    from tools import derive_container_writer_sinks as inventory
    violations = []
    for folder, directories, names in os.walk(root):
        directories[:] = [name for name in directories if name not in {
            ".git", "__pycache__", ".pytest_cache", ".venv", "node_modules",
            "runtime", "build", "dist", "assets"}]
        for name in names:
            path = Path(folder) / name
            relative = path.relative_to(root).as_posix()
            if path.suffix not in {".py", ".ps1"}:
                continue
            if relative in PINNED_EXCLUSIONS:
                expected, _ = PINNED_EXCLUSIONS[relative]
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    violations.append((relative, "pinned bytes differ"))
                continue
            text = path.read_text(encoding="utf-8-sig")
            if path.suffix == ".py":
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    tree = ast.parse(text)
                parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
                os_names = {"os"}
                replace_names = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        os_names.update(alias.asname or alias.name for alias in node.names if alias.name == "os")
                    if isinstance(node, ast.ImportFrom) and node.module == "os":
                        replace_names.update(alias.asname or alias.name for alias in node.names if alias.name == "replace")
                for node in ast.walk(tree):
                    direct = (isinstance(node, ast.Attribute) and (
                        node.attr in {"MoveFileExW", "ReplaceFileW"} or node.attr == "replace"
                        and isinstance(node.value, ast.Name) and node.value.id in os_names))
                    direct |= isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in replace_names
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
                            and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)):
                        direct |= node.args[1].value in {"MoveFileExW", "ReplaceFileW"} or (
                            node.args[1].value == "replace" and isinstance(node.args[0], ast.Name) and node.args[0].id in os_names)
                    if not direct:
                        continue
                    owner = node
                    while owner in parents and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        owner = parents[owner]
                    function = getattr(owner, "name", "module")
                    if (relative, function) == ("atomic_replace.py", "_replace_once") or (relative, function) in TEST_REPLACEMENT_DOUBLES:
                        continue
                    violations.append((relative, function, node.lineno))
    violations.extend(_powershell_replacements(root))
    return violations


def _powershell_replacements(root):
    import shutil
    from tests.powershell_contracts import run_powershell
    executable = shutil.which("pwsh") or shutil.which("powershell")
    assert executable is not None
    result = run_powershell([executable, "-NoProfile", "-File",
        str(ROOT / "tests/ca_atomic_ast_probe.ps1"), "-Root", str(root)],
        capture_output=True, text=True)
    assert result.returncode == 0
    rows = json.loads(result.stdout)
    violations = []
    for row in rows:
        relative = row["path"]
        if relative in PINNED_EXCLUSIONS:
            expected, _ = PINNED_EXCLUSIONS[relative]
            if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
                violations.append((relative, "changed pinned source"))
            continue
        if (relative, row["function"]) == ("tools/bootstrap_integrity.ps1", "Invoke-ContainerAtomicReplaceOnce"):
            continue
        if (relative, row["function"], row["sha256"]) not in MOVEMENT_EXCLUSIONS:
            violations.append((relative, row["function"], row["line"]))
    return violations


def test_fixed_canonical_exclusions_keep_exact_bytes_and_reason():
    assert len(PINNED_EXCLUSIONS) == 5
    for relative, (expected, reason) in PINNED_EXCLUSIONS.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected
        assert reason == "바이트 고정 정본 — 정본 주인 후속"


def test_no_direct_replacement_outside_owned_backend_or_named_pinned_source():
    assert _direct_replacements(ROOT) == []


def test_guard_rejects_new_direct_call_and_changed_canonical_bytes(tmp_path):
    path = tmp_path / "unexpected.py"
    path.write_text("import os\ndef unregistered(a,b):\n    os.replace(a,b)\n", encoding="utf-8")
    assert _direct_replacements(tmp_path)
    path.unlink()
    canonical = tmp_path / "shell/shell_fileio.py"
    canonical.parent.mkdir()
    canonical.write_text("# changed pinned source\n", encoding="utf-8")
    assert _direct_replacements(tmp_path)


@pytest.mark.parametrize("write_through", [False, True])
def test_ordered_reader_overlap_retries_the_same_prepared_file(tmp_path, monkeypatch, write_through):
    destination = tmp_path / "control.json"
    source = tmp_path / "prepared.json"
    destination.write_bytes(b'{"generation":1}')
    source.write_bytes(b'{"generation":2}')
    ready, release_reader, closed = (threading.Event() for _ in range(3))
    observations = []
    def reader():
        try:
            with destination.open("rb") as stream:
                observations.append(json.load(stream)["generation"])
                ready.set()
                assert release_reader.wait(5)
        finally:
            closed.set()
    worker = threading.Thread(target=reader)
    worker.start()
    assert ready.wait(5)
    original = publication._replace_once
    blocked = []
    def ordered_replace(prepared, target, durable):
        try:
            return original(prepared, target, durable)
        except OSError as error:
            blocked.append(error.winerror)
            assert source.exists() and destination.read_bytes() == b'{"generation":1}'
            release_reader.set()
            assert closed.wait(5)
            raise
    monkeypatch.setattr(publication, "_replace_once", ordered_replace)
    try:
        started = time.monotonic()
        publication.atomic_replace(source, destination, write_through=write_through)
        assert time.monotonic() - started < 2
    finally:
        release_reader.set()
        worker.join(5)
    assert not worker.is_alive()
    assert blocked and set(blocked) <= {5, 32}
    assert observations == [1]
    assert json.loads(destination.read_bytes()) == {"generation": 2}
    assert not source.exists()


@pytest.mark.parametrize("code", [5, 32])
def test_persistent_denial_preserves_first_exception_and_deadline(monkeypatch, code):
    first, later = ctypes.WinError(code), ctypes.WinError(code)
    now, attempts = [0.0], []
    def fail(*args):
        attempts.append(now[0])
        raise first if len(attempts) == 1 else later
    monkeypatch.setattr(publication, "_replace_once", fail)
    monkeypatch.setattr(publication, "monotonic", lambda: now[0])
    monkeypatch.setattr(publication, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    with pytest.raises(OSError) as result:
        publication.atomic_replace("prepared", "control")
    assert result.value is first and result.value.winerror == code
    assert len(attempts) > 1 and now[0] == pytest.approx(1.5)


@pytest.mark.parametrize("error", [ctypes.WinError(2), ctypes.WinError(87), PermissionError(13, "isolated denial")])
def test_non_transient_errors_never_retry_or_substitute_default(monkeypatch, error):
    attempts = []
    def fail(*args):
        attempts.append(args)
        raise error
    monkeypatch.setattr(publication, "_replace_once", fail)
    monkeypatch.setattr(publication, "sleep", lambda *_: pytest.fail("non-transient error retried"))
    with pytest.raises(OSError) as result:
        publication.atomic_replace("prepared", "control")
    assert result.value is error and len(attempts) == 1


def test_write_through_keeps_native_flags_and_winerror(monkeypatch):
    from types import SimpleNamespace
    calls = []
    def move(source, destination, flags):
        calls.append((source, destination, flags))
        return False
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: SimpleNamespace(MoveFileExW=move))
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 32)
    with pytest.raises(OSError) as result:
        publication._replace_once(Path("prepared"), Path("control"), True)
    assert result.value.winerror == 32 and calls == [("prepared", "control", 9)]


def test_control_document_consumer_retries_overlap_without_changing_reader(tmp_path, monkeypatch):
    import auto_update
    import writer_session_fence as fence
    destination = tmp_path / "active.json"
    destination.write_text('{"generation":1}', encoding="utf-8")
    reader = destination.open("rb")
    original = publication._replace_once
    blocked = []
    def release_on_first_denial(source, target, durable):
        assert durable is True
        assert fence._WRITER_EXIT_COUNT > 0 and fence._WRITER_LOCAL.depth > 0
        try:
            return original(source, target, durable)
        except OSError as error:
            blocked.append(error.winerror)
            reader.close()
            raise
    monkeypatch.setattr(publication, "_replace_once", release_on_first_denial)
    try:
        auto_update.write_json_durable(destination, {"generation": 2})
    finally:
        reader.close()
    assert blocked and set(blocked) <= {5, 32}
    assert auto_update.read_json(destination) == {"generation": 2}
    assert not list(tmp_path.glob("*.tmp"))


def test_prepared_packet_publication_retries_only_the_blocked_member(tmp_path, monkeypatch):
    import auto_update
    import writer_session_fence as fence
    names = ("manifest.json", "manifest.sig", "packet.zip")
    prepared = {}
    for name in names:
        (tmp_path / name).write_bytes(b"old")
        prepared[name] = tmp_path / (name + ".tmp")
        prepared[name].write_bytes(b"new")
    reader = (tmp_path / "manifest.sig").open("rb")
    original = publication._replace_once
    attempts = []
    def once(source, target, durable):
        attempts.append(target.name)
        assert durable is False and fence._WRITER_EXIT_COUNT > 0 and fence._WRITER_LOCAL.depth > 0
        try:
            return original(source, target, durable)
        except OSError:
            reader.close()
            raise
    monkeypatch.setattr(publication, "_replace_once", once)
    try:
        auto_update.publish_download(tmp_path, prepared)
    finally:
        reader.close()
    assert attempts == ["manifest.json", "manifest.sig", "manifest.sig", "packet.zip"]
    assert all((tmp_path / name).read_bytes() == b"new" for name in names)
    assert not any(path.exists() for path in prepared.values())


def test_transfer_keeps_original_arguments_callers_and_fence_classifications():
    import subprocess
    from collections import Counter
    baseline = "fbfada019d08b0aae102282ed601560b68f7fb17"
    def signature(tree, direct):
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        rows = []
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            matches = (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                       and call.func.value.id == "os" and call.func.attr == "replace") if direct else (
                       isinstance(call.func, ast.Name) and call.func.id == "atomic_replace")
            if not matches:
                continue
            node = call
            owner = None
            while node in parents:
                node = parents[node]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = node
                    break
            assert owner is not None
            rows.append((owner.name, ast.dump(ast.Tuple(elts=call.args, ctx=ast.Load())),
                         tuple(ast.dump(decorator) for decorator in owner.decorator_list),
                         tuple(ast.dump(node.items[0].context_expr) for node in ast.walk(owner) if isinstance(node, ast.With))))
        return Counter(rows)
    old_count = new_count = 0
    for path in [*ROOT.glob("*.py"), *ROOT.joinpath("tools").glob("*.py")]:
        if path.name == "atomic_replace.py":
            continue
        relative = path.relative_to(ROOT).as_posix()
        old = subprocess.check_output(["git", "-C", str(ROOT), "show", baseline + ":" + relative], stderr=subprocess.DEVNULL)
        before = ast.parse(old.decode("utf-8-sig"))
        after = ast.parse(path.read_text(encoding="utf-8-sig"))
        old_rows, new_rows = signature(before, True), signature(after, False)
        assert old_rows == new_rows
        old_count += sum(old_rows.values());new_count += sum(new_rows.values())
        if relative == "auto_update.py":
            old_read = next(node for node in before.body if isinstance(node, ast.FunctionDef) and node.name == "read_json")
            new_read = next(node for node in after.body if isinstance(node, ast.FunctionDef) and node.name == "read_json")
            assert ast.dump(old_read) == ast.dump(new_read)
            rename = lambda tree: [ast.dump(node) for node in ast.walk(tree) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os" and node.func.attr == "rename"]
            assert rename(before) == rename(after)
    assert old_count == new_count == 36


@pytest.mark.parametrize("directory", ["vendor", "ui"])
def test_guard_scans_owned_subdirectories(tmp_path, directory):
    target=tmp_path/directory/"publication.py"
    target.parent.mkdir()
    target.write_text("import os; os.replace('a','b')\n", encoding="utf-8")
    assert _direct_replacements(tmp_path)


@pytest.mark.parametrize("source", [
    "Microsoft.PowerShell.Management\\Move-Item -LiteralPath $a -Destination $b",
    "Rename-Item -LiteralPath $a -NewName $b",
    "[System.IO.File]::Replace(\n$a,\n$b,\n$c\n)",
])
def test_guard_parses_powershell_commands_and_multiline_calls(tmp_path, source):
    (tmp_path/"publication.ps1").write_text(source,encoding="utf-8")
    assert _powershell_replacements(tmp_path)


def test_retry_sleep_past_deadline_prevents_later_native_call(monkeypatch):
    now=[0.0];attempts=[];first=ctypes.WinError(5)
    def replace(*args):
        attempts.append(now[0])
        if len(attempts)==1: raise first
    monkeypatch.setattr(publication,"_replace_once",replace)
    monkeypatch.setattr(publication,"monotonic",lambda:now[0])
    monkeypatch.setattr(publication,"sleep",lambda _:now.__setitem__(0,2.0))
    with pytest.raises(OSError) as failure:
        publication.atomic_replace("prepared","target")
    assert failure.value is first and attempts==[0.0]


@pytest.mark.parametrize("deadline",[0.0,0.1])
def test_explicit_publication_budget_preserves_first_error(monkeypatch,deadline):
    now=[0.0];attempts=[];first=ctypes.WinError(32)
    def replace(*args):
        attempts.append(now[0]);raise first
    monkeypatch.setattr(publication,"_replace_once",replace)
    monkeypatch.setattr(publication,"monotonic",lambda:now[0])
    monkeypatch.setattr(publication,"sleep",lambda _:now.__setitem__(0,deadline+0.01))
    with pytest.raises(OSError) as failure:
        publication.atomic_replace("prepared","target",deadline=deadline)
    assert failure.value is first and attempts==[0.0]

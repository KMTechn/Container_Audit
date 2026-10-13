import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tests.test_direct_sync_relay_runner import fixed_runner_clock


ROOT = Path(__file__).resolve().parents[1]
MODE = "--container-audit-direct-sync-relay"
CHILD = r'''
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
import time

root = Path(sys.argv[1])
gate_result = None if sys.argv[2] == "allow" else int(sys.argv[2])
outcome = sys.argv[3]
sys.path.insert(0, str(root))
before = len(sys.modules)
started = time.perf_counter()
import auto_update
import container_audit_product_host as host
from tools import direct_sync_relay_runner as runner

calls = []
def gate(app_root, arguments, *, role="gui"):
    calls.append(["gate", str(app_root), list(arguments), role])
    return gate_result
auto_update.startup_gate = gate

def relay(arguments):
    calls.append(["runner", list(arguments)])
    if outcome == "exit":
        raise SystemExit(7)
    if outcome == "error":
        raise RuntimeError("relay failure")
    return 17
runner.main = relay
# Existing host evidence writes are covered separately; keep this child read-only.
host._record_hosted_relay_failure = lambda arguments, error: calls.append(
    ["failure", list(arguments), type(error).__name__]
)

class ApplicationLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "Container_Audit":
            return importlib.util.spec_from_loader(fullname, self)
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        calls.append(["application_import"])
        module.main = lambda: host.dispatch_product_mode(sys.argv[1:])
sys.meta_path.insert(0, ApplicationLoader())

entry_path = root / "portable" / "main.py"
sys.argv = [str(entry_path), "--container-audit-direct-sync-relay", "--db-path", "queue.sqlite3"]
spec = importlib.util.spec_from_file_location("portable_entry", entry_path)
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
# Installed main.py and the product host share app/; reproduce that layout.
entry.APP_ROOT = root
try:
    result = entry.main()
except SystemExit as error:
    result = error.code
print(json.dumps({
    "result": result,
    "calls": calls,
    "application_loaded": "Container_Audit" in sys.modules,
    "module_count": len(sys.modules),
    "modules_added": len(sys.modules) - before,
    "seconds": time.perf_counter() - started,
}))
'''


@pytest.mark.parametrize(
    ("gate", "outcome", "expected"),
    [("allow", "return", 17), ("allow", "exit", 7), ("allow", "error", 1),
     ("0", "return", 0), ("20", "return", 20)],
)
def test_relay_child_uses_guarded_host_without_application_import(gate, outcome, expected, record_property):
    child = subprocess.run(
        [sys.executable, "-I", "-B", "-c", CHILD, str(ROOT), gate, outcome],
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert child.returncode == 0
    observed = json.loads(child.stdout)
    assert observed["application_loaded"] is False
    assert observed["calls"][0] == ["gate", str(ROOT), [MODE, "--db-path", "queue.sqlite3"], "relay"]
    assert sum(call[0] == "gate" for call in observed["calls"]) == 1
    assert observed["result"] == expected
    if gate == "allow":
        assert observed["calls"][1] == ["runner", ["--db-path", "queue.sqlite3"]]
    else:
        assert len(observed["calls"]) == 1
    # Record only loading metrics, never runner input or diagnostic payloads.
    for name in ("module_count", "modules_added", "seconds"):
        record_property(name, observed[name])


def test_portable_runner_matches_host_receipt_and_status_bytes(
    tmp_path, monkeypatch, capsys, fixed_runner_clock,
):
    import hashlib
    from types import SimpleNamespace
    import uuid

    import auto_update
    import container_audit_product_host as host
    import direct_sync_push as push
    import direct_sync_runtime as runtime
    from tests.test_direct_sync_relay_runner import (
        AcceptedReceiptSession, install_receipt_test_runtime, relay_rows,
        runner_args, write_container_csv,
    )

    monkeypatch.setattr(auto_update, "startup_gate", lambda *_args, **_kwargs: None)
    now = lambda: "2033-05-18T03:33:20Z"
    monkeypatch.setattr(push, "utc_now_text", now)
    monkeypatch.setattr(runtime, "utc_now_text", now)
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID(int=1))
    monkeypatch.setattr(runtime.shutil, "disk_usage", lambda _path: SimpleNamespace(
        total=10**12, used=10**9, free=10**12 - 10**9,
    ))
    session = AcceptedReceiptSession()
    install_receipt_test_runtime(monkeypatch, session)
    source = tmp_path / "events"
    write_container_csv(source)
    arguments = [MODE, *runner_args(tmp_path, scan_dir=source), "--drain-after-scan"]
    inputs = {path for path in tmp_path.rglob("*") if path.is_file()}

    def snapshot():
        paths = [tmp_path / "runtime/status.json", tmp_path / "logs/relay.jsonl"]
        paths.extend((tmp_path / "status").glob("*.json"))
        return sorted((str(path.relative_to(tmp_path)), hashlib.sha256(path.read_bytes()).hexdigest())
                      for path in paths)

    assert host.dispatch_product_mode(arguments) == 0
    assert relay_rows(tmp_path / "relay.sqlite3")[0]["status"] == "acked"
    assert len(session.calls) == 1
    previous = snapshot()
    previous_output = capsys.readouterr().out
    previous_request = hashlib.sha256(session.calls[0]["file_bytes"]).hexdigest()
    previous_metadata = hashlib.sha256(json.dumps(
        session.calls[0]["metadata"], sort_keys=True,
    ).encode()).hexdigest()
    # Reuse exact paths and original inputs; remove only files created by this run.
    for path in tmp_path.rglob("*"):
        if path.is_file() and path not in inputs:
            assert path.is_relative_to(tmp_path) and not path.is_symlink()
            path.unlink()
    session.calls.clear()

    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "argv", ["main.py", *arguments])
    spec = importlib.util.spec_from_file_location("portable_receipt_entry", ROOT / "portable/main.py")
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)
    entry.APP_ROOT = ROOT
    assert entry.main() == 0
    assert relay_rows(tmp_path / "relay.sqlite3")[0]["status"] == "acked"
    assert len(session.calls) == 1
    assert snapshot() == previous
    assert capsys.readouterr().out == previous_output
    assert hashlib.sha256(session.calls[0]["file_bytes"]).hexdigest() == previous_request
    assert hashlib.sha256(json.dumps(
        session.calls[0]["metadata"], sort_keys=True,
    ).encode()).hexdigest() == previous_metadata

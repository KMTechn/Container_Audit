import ast
import inspect
import json
import textwrap
from pathlib import Path

from Container_Audit import ContainerAudit


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_STREAM_CATALOG = (
    ROOT
    / "kmtech_factory_contracts"
    / "bundle"
    / "v1"
    / "catalogs"
    / "canonical-stream-catalog.json"
)


def _literal_log_events(method):
    tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
    return {
        call.args[0].value
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "_log_event"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    }


def test_current_tray_restore_runtime_event_is_authorized_by_canonical_catalog():
    runtime_events = _literal_log_events(ContainerAudit._load_current_tray_state)
    catalog = json.loads(CANONICAL_STREAM_CATALOG.read_text(encoding="utf-8"))
    stream = next(
        entry
        for entry in catalog["streams"]
        if entry.get("app_id") == "container_audit"
        and entry.get("stream_id") == "container_audit_events"
    )

    assert "TRAY_RESTORE" in runtime_events
    assert "TRAY_RESTORE" in stream["raw_event_names"]

from __future__ import annotations

import ast
import threading
from pathlib import Path

import pytest

import Container_Audit as container_module
import transfer_seal as transfer_seal_module
from Container_Audit import ContainerAudit, TraySession
from tests.test_container_p0_contracts import _cross_thread_fake_root
from tk_serial_ui_lane import TkSerialUiLane
from transfer_member_exchange import TransferMemberExchangeStore
from transfer_seal import (
    TransferSealCoordinator,
    TransferSealStore,
)


ROOT = Path(__file__).resolve().parents[1]

READ_ONLY_ALLOWLIST = {
    ("transfer_seal.py", "TransferSealStore"): {
        "preview_intent",
        "load",
        "precommand_operator_review",
        "pending_ids",
        "post_review_case_for_intent",
        "post_review_cases",
        "pending_post_review_projections",
        "has_exact_history",
        "replacement_waiting_outbox",
        "pending_replacement_waiting_projections",
    },
    ("transfer_seal.py", "TransferSealCoordinator"): {"preview"},
    ("transfer_member_exchange.py", "TransferMemberExchangeStore"): {
        "load",
        "has_dismissed_command_fence",
        "pending_ids",
        "pending_local_rows",
        "blocking_rows",
    },
    ("transfer_member_exchange.py", "TransferMemberExchangeCoordinator"): {
        "pending_local_attempts",
    },
}

OWNER_BIND_METHOD = "bind_owner_thread_id_provider"
STORE_CLASS_NAMES = {"TransferSealStore", "TransferMemberExchangeStore"}
COORDINATOR_CLASS_NAMES = {
    "TransferSealCoordinator",
    "TransferMemberExchangeCoordinator",
}


def _classes(filename: str):
    tree = ast.parse(
        (ROOT / filename).read_text(encoding="utf-8"),
        filename=filename,
    )
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }


def _public_methods(class_node: ast.ClassDef):
    return {
        node.name: node
        for node in class_node.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    }


def _first_executable_statement(method: ast.FunctionDef):
    statements = list(method.body)
    if (
        statements
        and isinstance(statements[0], ast.Expr)
        and isinstance(statements[0].value, ast.Constant)
        and isinstance(statements[0].value.value, str)
    ):
        statements = statements[1:]
    return statements[0] if statements else None


def _call_name(call: ast.Call) -> str:
    try:
        return ast.unparse(call.func)
    except (AttributeError, ValueError):
        return ""


def _constant_sql_writes(method: ast.FunctionDef):
    writes = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = _call_name(node)
        if not name.endswith((".execute", ".executemany", ".executescript")):
            continue
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            continue
        sql = " ".join(first.value.upper().split())
        if any(
            keyword in sql
            for keyword in (
                "INSERT ",
                "UPDATE ",
                "DELETE ",
                "REPLACE ",
                "CREATE ",
                "ALTER ",
                "DROP ",
            )
        ):
            writes.append(sql)
    return writes


def _central_calls(method: ast.FunctionDef):
    return [
        _call_name(node)
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and _call_name(node).startswith("self.client.")
    ]


def _method_calls(method: ast.FunctionDef):
    return {
        _call_name(node)
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
    }


def _writer_surfaces():
    surfaces = []
    for key, read_only in READ_ONLY_ALLOWLIST.items():
        filename, class_name = key
        methods = _public_methods(_classes(filename)[class_name])
        excluded = set(read_only)
        if class_name in STORE_CLASS_NAMES:
            excluded.add(OWNER_BIND_METHOD)
        for method_name in sorted(set(methods) - excluded):
            surfaces.append((filename, class_name, method_name))
    return surfaces


WRITER_SURFACES = _writer_surfaces()


@pytest.mark.parametrize(
    ("filename", "class_name", "method_name"),
    WRITER_SURFACES,
    ids=lambda value: str(value),
)
def test_every_public_transfer_writer_asserts_owner_first(
    filename,
    class_name,
    method_name,
):
    class_node = _classes(filename)[class_name]
    methods = _public_methods(class_node)
    method = methods[method_name]
    calls = _method_calls(method)
    if class_name in STORE_CLASS_NAMES:
        assert _constant_sql_writes(method), (
            filename,
            class_name,
            method_name,
            "public non-read surface has no mechanically visible SQLite write",
        )
        required_assertion = "self._assert_coordinator_owner"
    else:
        store_class_name = (
            "TransferSealStore"
            if class_name == "TransferSealCoordinator"
            else "TransferMemberExchangeStore"
        )
        store_key = (filename, store_class_name)
        store_methods = _public_methods(_classes(filename)[store_class_name])
        store_writers = set(store_methods) - READ_ONLY_ALLOWLIST[store_key] - {
            OWNER_BIND_METHOD
        }
        mutation_calls = {
            f"self.store.{name}" for name in store_writers
        }
        assert (
            _central_calls(method)
            or calls & mutation_calls
            or calls
            & {
                "self.attempt",
                "self.operation_lease_manager.accept_rotation",
                "self.operation_lease_manager.store.record_local_completion",
                "self.operation_lease_manager.store.record_receipt",
                "self.operation_lease_manager.store.record_review",
            }
        ), (filename, class_name, method_name, "writer evidence missing")
        required_assertion = "self._assert_owner"

    first = _first_executable_statement(method)
    assert isinstance(first, ast.Expr), (
        filename,
        class_name,
        method_name,
        ast.dump(first) if first is not None else None,
    )
    assert isinstance(first.value, ast.Call)
    assert _call_name(first.value) == required_assertion


@pytest.mark.parametrize(
    ("filename", "class_name", "method_name"),
    [
        (filename, class_name, method_name)
        for (filename, class_name), method_names in READ_ONLY_ALLOWLIST.items()
        for method_name in sorted(method_names)
    ],
)
def test_transfer_read_only_allowlist_has_no_write_or_central_call(
    filename,
    class_name,
    method_name,
):
    methods = _public_methods(_classes(filename)[class_name])
    assert method_name in methods
    method = methods[method_name]
    assert _constant_sql_writes(method) == []
    assert _central_calls(method) == []


@pytest.mark.parametrize(
    "store_type",
    [TransferSealStore, TransferMemberExchangeStore],
)
def test_transfer_owner_provider_binding_is_one_shot(tmp_path, store_type):
    binding_error = getattr(
        transfer_seal_module,
        "TransferCoordinatorOwnerBindingError",
        None,
    )
    assert binding_error is not None
    owner_id = threading.get_ident()
    first_provider = lambda: owner_id
    different_provider = lambda: owner_id
    store = store_type(
        tmp_path / f"{store_type.__name__}.db",
        owner_thread_id_provider=first_provider,
    )

    store.bind_owner_thread_id_provider(first_provider)
    with pytest.raises(binding_error) as raised:
        store.bind_owner_thread_id_provider(different_provider)

    assert raised.value.code == "TRANSFER_COORDINATOR_OWNER_REBIND"


def test_suite_wide_headless_guard_covers_container_aliases(
    headless_gui_error_type,
):
    for entry_point in (
        lambda: container_module.messagebox.Message(),
        lambda: container_module.messagebox.showwarning("title", "message"),
        lambda: container_module.simpledialog.askstring("title", "prompt"),
        lambda: container_module.tk.Toplevel(),
        lambda: container_module.tk.Tk(),
    ):
        with pytest.raises(headless_gui_error_type):
            entry_point()


def test_tk_exact_history_uses_lane_snapshot_during_post_review_work(
    tmp_path,
    request,
):
    root = _cross_thread_fake_root()
    lane = TkSerialUiLane(root, poll_ms=1)

    def close_lane():
        if lane.state not in {"CLOSED", "BROKEN"}:
            lane.close_idle()
            root.run_until(lambda: lane.state == "CLOSED", timeout=12.0)

    request.addfinalizer(close_lane)
    owner_provider = lambda: lane.worker_thread_id
    store = TransferSealStore(
        tmp_path / "transfer.db",
        owner_thread_id_provider=owner_provider,
    )
    coordinator = TransferSealCoordinator(
        store,
        None,
        owner_thread_id_provider=owner_provider,
    )
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = root
    app._ui_lane = lane
    app.transfer_seal_coordinator = coordinator
    app.transfer_member_exchange_coordinator = None
    app.current_tray = TraySession()
    app._ui_close_requested = False
    app._scan_callback_epoch = 1
    app._transfer_post_review_refresh_pending = False
    app._transfer_post_review_refresh_inflight = False
    app._post_review_refresh_required = False
    app._presented_post_review_case_ids = set()
    app._member_exchange_reconcile_pending = False
    app._member_exchange_reconcile_inflight = False
    app._exact_exchange_mode_active = False
    app._exact_transfer_exchange_history_snapshot = False
    app._precommand_operator_review_query = lambda: None

    entered = threading.Event()
    release = threading.Event()
    read_threads = []
    original_has_exact_history = store.has_exact_history

    def blocking_drain():
        entered.set()
        assert release.wait(timeout=10.0)
        return 0

    def observing_has_exact_history():
        read_threads.append(threading.get_ident())
        return original_has_exact_history()

    app._drain_transfer_post_review_projections = blocking_drain
    store.has_exact_history = observing_has_exact_history
    try:
        assert app._refresh_transfer_post_review_state() is True
        assert entered.wait(timeout=5.0)
        assert lane.is_busy() is True

        # Conservative busy admission uses only the last copied value.  The
        # Tk thread does not enter SQLite while the lane owns post-review work.
        assert app._exact_transfer_exchange_blocked() is True
        assert read_threads == []
    finally:
        release.set()

    root.run_until(lambda: not lane.is_busy(), timeout=12.0)
    assert read_threads == [lane.worker_thread_id]
    assert app._exact_transfer_exchange_history_snapshot is False
    assert app._exact_transfer_exchange_blocked() is False
    lane.close_idle()
    root.run_until(lambda: lane.state == "CLOSED", timeout=12.0)


def test_tk_state_consumers_have_no_direct_store_call():
    class_node = _classes("Container_Audit.py")["ContainerAudit"]
    methods = _public_methods(class_node)
    for method_name in (
        "_update_action_button_states",
        "_show_operations_menu",
        "_exact_transfer_exchange_blocked",
        "_current_transfer_member_exchange_attempt",
        "_precommand_operator_review_retry_context",
        "_transfer_member_exchange_blocks_local_action",
    ):
        method = next(
            node
            for node in class_node.body
            if isinstance(node, ast.FunctionDef) and node.name == method_name
        )
        direct_store_calls = [
            _call_name(node)
            for node in ast.walk(method)
            if isinstance(node, ast.Call) and ".store." in _call_name(node)
        ]
        assert direct_store_calls == [], (method_name, direct_store_calls)

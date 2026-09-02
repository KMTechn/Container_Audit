from __future__ import annotations

import ast
import functools
import operator
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import Container_Audit as container_module
import transfer_seal as transfer_seal_module
from tests import transfer_read_runtime_helper
from Container_Audit import ContainerAudit, TraySession
from tests.test_container_p0_contracts import _cross_thread_fake_root
from tk_serial_ui_lane import TkSerialUiLane
from transfer_member_exchange import TransferMemberExchangeStore
from transfer_seal import (
    TransferSealCoordinator,
    TransferSealStore,
    TransferCoordinatorUiThreadBindingError,
    TransferCoordinatorUiThreadReadError,
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
UI_THREAD_BIND_METHOD = "bind_ui_thread_id_provider"
STORE_CLASS_NAMES = {"TransferSealStore", "TransferMemberExchangeStore"}
COORDINATOR_CLASS_NAMES = {
    "TransferSealCoordinator",
    "TransferMemberExchangeCoordinator",
}


def _runtime_read_local_alias(self):
    audit9_store_alias = self.transfer_seal_coordinator.store
    return audit9_store_alias.has_exact_history()


def _runtime_read_bound_method(self):
    audit10_bound_read = self.transfer_seal_coordinator.store.has_exact_history
    return audit10_bound_read()


def _runtime_read_attribute_chain(self):
    return self._svc.store.has_exact_history()


def _runtime_read_getattr(self):
    return getattr(
        self.transfer_seal_coordinator.store,
        "has_exact_history",
    )()


def _runtime_read_immediate_lambda(self):
    return (lambda: self.transfer_seal_coordinator.store.has_exact_history())()


def _runtime_read_immediate_nested(self):
    def audit10_nested_read():
        return self.transfer_seal_coordinator.store.has_exact_history()

    return audit10_nested_read()


def _runtime_read_comprehension(self):
    return [
        self.transfer_seal_coordinator.store.has_exact_history()
        for _index in range(1)
    ][0]


def _runtime_read_partial(self):
    return functools.partial(
        self.transfer_seal_coordinator.store.has_exact_history
    )()


def _runtime_read_methodcaller(self):
    return operator.methodcaller("has_exact_history")(
        self.transfer_seal_coordinator.store
    )


def _runtime_read_tuple_list_alias(self):
    (audit10_store,) = (self.transfer_seal_coordinator.store,)
    audit10_list = [audit10_store]
    return audit10_list[0].has_exact_history()


def _runtime_read_imported_helper(self):
    return transfer_read_runtime_helper.has_exact_history(
        self.transfer_seal_coordinator.store
    )


def _runtime_read_unbound_descriptor(self):
    store = self.transfer_seal_coordinator.store
    return type(store).has_exact_history(store)


def _runtime_read_private_connect(self):
    with self.transfer_seal_coordinator.store._connect():
        return False


RUNTIME_UI_READ_VARIANTS = (
    ("audit9-local-alias", _runtime_read_local_alias),
    ("bound-method", _runtime_read_bound_method),
    ("attribute-chain", _runtime_read_attribute_chain),
    ("getattr", _runtime_read_getattr),
    ("immediate-lambda", _runtime_read_immediate_lambda),
    ("immediate-nested-function", _runtime_read_immediate_nested),
    ("list-comprehension", _runtime_read_comprehension),
    ("functools-partial", _runtime_read_partial),
    ("operator-methodcaller", _runtime_read_methodcaller),
    ("tuple-unpack-list-index", _runtime_read_tuple_list_alias),
    ("imported-module-helper", _runtime_read_imported_helper),
    ("unbound-descriptor", _runtime_read_unbound_descriptor),
    ("private-connect-backstop", _runtime_read_private_connect),
)


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


def _binding_name(node: ast.AST) -> str:
    if not isinstance(node, (ast.Name, ast.Attribute)):
        return ""
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return ""


class _TkDirectStoreReadAnalyzer:
    """Follow store aliases and synchronous local helpers from Tk roots."""

    _FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)

    def __init__(self, tree: ast.Module, class_name: str):
        self._class_node = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        )
        self._methods = {
            node.name: node
            for node in self._class_node.body
            if isinstance(node, self._FUNCTION_NODES)
        }
        self._module_functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, self._FUNCTION_NODES)
        }
        self._active_calls = set()

    def find_reads(self, root_names):
        reads = set()
        for root_name in root_names:
            self._analyze_function(
                ("method", root_name),
                set(),
                (root_name,),
                reads,
            )
        return sorted(reads)

    def _definition(self, key):
        kind, name = key
        return self._methods[name] if kind == "method" else self._module_functions[name]

    def _resolve_call(self, call: ast.Call):
        func = call.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "self"
            and func.attr in self._methods
        ):
            return ("method", func.attr)
        if isinstance(func, ast.Name) and func.id in self._module_functions:
            return ("module", func.id)
        return None

    @staticmethod
    def _parameter_names(function, *, bound_method):
        positional = list(function.args.posonlyargs) + list(function.args.args)
        if bound_method and positional:
            positional = positional[1:]
        return positional, list(function.args.kwonlyargs)

    def _tainted_call_parameters(
        self,
        function,
        *,
        bound_method,
        positional_taints,
        keyword_taints,
    ):
        positional, keyword_only = self._parameter_names(
            function,
            bound_method=bound_method,
        )
        tainted = {
            parameter.arg
            for parameter, is_store in zip(positional, positional_taints)
            if is_store
        }
        known_keywords = {
            parameter.arg for parameter in positional + keyword_only
        }
        tainted.update(
            name
            for name, is_store in keyword_taints.items()
            if name in known_keywords and is_store
        )
        if function.args.vararg is not None and any(
            positional_taints[len(positional) :]
        ):
            tainted.add(function.args.vararg.arg)
        if function.args.kwarg is not None and any(
            is_store
            for name, is_store in keyword_taints.items()
            if name not in known_keywords
        ):
            tainted.add(function.args.kwarg.arg)
        return tainted

    def _analyze_function(self, key, tainted_parameters, path, reads):
        context = (key, tuple(sorted(tainted_parameters)))
        if context in self._active_calls:
            return False
        self._active_calls.add(context)
        try:
            function = self._definition(key)
            environment = set(tainted_parameters)
            _, returns_store = self._analyze_block(
                function.body,
                environment,
                path,
                reads,
            )
            return returns_store
        finally:
            self._active_calls.remove(context)

    def _record_store_call(self, call, path, reads):
        reads.add(
            f"{' -> '.join(path)}:{_call_name(call)}@{getattr(call, 'lineno', '?')}"
        )

    def _expression_is_store(self, node, environment, path, reads):
        if node is None:
            return False
        binding = _binding_name(node)
        if binding and binding in environment:
            return True
        if isinstance(node, ast.Name):
            return node.id in environment
        if isinstance(node, ast.Attribute):
            owner_is_store = self._expression_is_store(
                node.value,
                environment,
                path,
                reads,
            )
            return node.attr == "store" or owner_is_store
        if isinstance(node, ast.Call):
            receiver_is_store = False
            if isinstance(node.func, ast.Attribute):
                receiver_is_store = self._expression_is_store(
                    node.func.value,
                    environment,
                    path,
                    reads,
                )
            elif self._expression_is_store(
                node.func,
                environment,
                path,
                reads,
            ):
                receiver_is_store = True
            if receiver_is_store:
                self._record_store_call(node, path, reads)

            positional_taints = [
                self._expression_is_store(arg, environment, path, reads)
                for arg in node.args
            ]
            keyword_taints = {
                keyword.arg: self._expression_is_store(
                    keyword.value,
                    environment,
                    path,
                    reads,
                )
                for keyword in node.keywords
                if keyword.arg is not None
            }
            expanded_keyword_taints = [
                self._expression_is_store(
                    keyword.value,
                    environment,
                    path,
                    reads,
                )
                for keyword in node.keywords
                if keyword.arg is None
            ]
            target = self._resolve_call(node)
            if target is None:
                return False
            function = self._definition(target)
            tainted_parameters = self._tainted_call_parameters(
                function,
                bound_method=target[0] == "method",
                positional_taints=positional_taints,
                keyword_taints=keyword_taints,
            )
            if function.args.kwarg is not None and any(expanded_keyword_taints):
                tainted_parameters.add(function.args.kwarg.arg)
            return self._analyze_function(
                target,
                tainted_parameters,
                path + (target[1],),
                reads,
            )
        if isinstance(node, ast.NamedExpr):
            is_store = self._expression_is_store(
                node.value,
                environment,
                path,
                reads,
            )
            self._bind(node.target, is_store, environment)
            return is_store
        if isinstance(node, ast.IfExp):
            self._expression_is_store(node.test, environment, path, reads)
            return any(
                self._expression_is_store(branch, environment, path, reads)
                for branch in (node.body, node.orelse)
            )
        if isinstance(node, ast.BoolOp):
            return any(
                self._expression_is_store(value, environment, path, reads)
                for value in node.values
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(
                self._expression_is_store(value, environment, path, reads)
                for value in node.elts
            )
        if isinstance(node, ast.Dict):
            key_taints = [
                self._expression_is_store(key, environment, path, reads)
                for key in node.keys
                if key is not None
            ]
            value_taints = [
                self._expression_is_store(value, environment, path, reads)
                for value in node.values
            ]
            return any(key_taints + value_taints)
        if isinstance(node, ast.Subscript):
            value_is_store = self._expression_is_store(
                node.value,
                environment,
                path,
                reads,
            )
            self._expression_is_store(node.slice, environment, path, reads)
            return value_is_store

        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._expression_is_store(child, environment, path, reads)
        return False

    @staticmethod
    def _bind(target, is_store, environment):
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                _TkDirectStoreReadAnalyzer._bind(
                    element,
                    is_store,
                    environment,
                )
            return
        binding = _binding_name(target)
        if not binding:
            return
        if is_store:
            environment.add(binding)
        else:
            environment.discard(binding)

    def _analyze_block(self, statements, environment, path, reads):
        returns_store = False
        for statement in statements:
            if isinstance(statement, ast.Assign):
                is_store = self._expression_is_store(
                    statement.value,
                    environment,
                    path,
                    reads,
                )
                for target in statement.targets:
                    self._bind(target, is_store, environment)
            elif isinstance(statement, ast.AnnAssign):
                is_store = self._expression_is_store(
                    statement.value,
                    environment,
                    path,
                    reads,
                )
                self._bind(statement.target, is_store, environment)
            elif isinstance(statement, ast.AugAssign):
                is_store = self._expression_is_store(
                    statement.target,
                    environment,
                    path,
                    reads,
                ) or self._expression_is_store(
                    statement.value,
                    environment,
                    path,
                    reads,
                )
                self._bind(statement.target, is_store, environment)
            elif isinstance(statement, ast.Expr):
                self._expression_is_store(
                    statement.value,
                    environment,
                    path,
                    reads,
                )
            elif isinstance(statement, ast.Return):
                returns_store = self._expression_is_store(
                    statement.value,
                    environment,
                    path,
                    reads,
                ) or returns_store
            elif isinstance(statement, ast.If):
                self._expression_is_store(
                    statement.test,
                    environment,
                    path,
                    reads,
                )
                body_environment, body_returns = self._analyze_block(
                    statement.body,
                    set(environment),
                    path,
                    reads,
                )
                else_environment, else_returns = self._analyze_block(
                    statement.orelse,
                    set(environment),
                    path,
                    reads,
                )
                environment.clear()
                environment.update(body_environment | else_environment)
                returns_store = returns_store or body_returns or else_returns
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                iterator_is_store = self._expression_is_store(
                    statement.iter,
                    environment,
                    path,
                    reads,
                )
                body_environment = set(environment)
                self._bind(statement.target, iterator_is_store, body_environment)
                body_environment, body_returns = self._analyze_block(
                    statement.body,
                    body_environment,
                    path,
                    reads,
                )
                else_environment, else_returns = self._analyze_block(
                    statement.orelse,
                    set(environment),
                    path,
                    reads,
                )
                environment.update(body_environment | else_environment)
                returns_store = returns_store or body_returns or else_returns
            elif isinstance(statement, ast.While):
                self._expression_is_store(
                    statement.test,
                    environment,
                    path,
                    reads,
                )
                body_environment, body_returns = self._analyze_block(
                    statement.body,
                    set(environment),
                    path,
                    reads,
                )
                else_environment, else_returns = self._analyze_block(
                    statement.orelse,
                    set(environment),
                    path,
                    reads,
                )
                environment.update(body_environment | else_environment)
                returns_store = returns_store or body_returns or else_returns
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                body_environment = set(environment)
                for item in statement.items:
                    is_store = self._expression_is_store(
                        item.context_expr,
                        environment,
                        path,
                        reads,
                    )
                    if item.optional_vars is not None:
                        self._bind(item.optional_vars, is_store, body_environment)
                body_environment, body_returns = self._analyze_block(
                    statement.body,
                    body_environment,
                    path,
                    reads,
                )
                environment.update(body_environment)
                returns_store = returns_store or body_returns
            elif isinstance(statement, ast.Try):
                branch_environments = []
                branch_returns = []
                for branch in (
                    statement.body,
                    statement.orelse,
                    statement.finalbody,
                    *(handler.body for handler in statement.handlers),
                ):
                    branch_environment, branch_return = self._analyze_block(
                        branch,
                        set(environment),
                        path,
                        reads,
                    )
                    branch_environments.append(branch_environment)
                    branch_returns.append(branch_return)
                for branch_environment in branch_environments:
                    environment.update(branch_environment)
                returns_store = returns_store or any(branch_returns)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            else:
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.expr):
                        self._expression_is_store(
                            child,
                            environment,
                            path,
                            reads,
                        )
        return environment, returns_store


def _tk_direct_store_read_paths(filename, class_name, root_names):
    tree = ast.parse(
        (ROOT / filename).read_text(encoding="utf-8"),
        filename=filename,
    )
    return _TkDirectStoreReadAnalyzer(tree, class_name).find_reads(root_names)


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
            excluded.update({OWNER_BIND_METHOD, UI_THREAD_BIND_METHOD})
        for method_name in sorted(set(methods) - excluded):
            surfaces.append((filename, class_name, method_name))
    return surfaces


WRITER_SURFACES = _writer_surfaces()


def test_transfer_writer_owner_census_remains_exactly_25():
    counts = {
        class_name: sum(
            1
            for _filename, observed_class, _method_name in WRITER_SURFACES
            if observed_class == class_name
        )
        for class_name in sorted(STORE_CLASS_NAMES | COORDINATOR_CLASS_NAMES)
    }
    assert counts == {
        "TransferMemberExchangeCoordinator": 4,
        "TransferMemberExchangeStore": 7,
        "TransferSealCoordinator": 5,
        "TransferSealStore": 9,
    }
    assert len(WRITER_SURFACES) == 25


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
            OWNER_BIND_METHOD,
            UI_THREAD_BIND_METHOD,
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
    first = _first_executable_statement(method)
    assert isinstance(first, ast.Expr)
    assert isinstance(first.value, ast.Call)
    assert _call_name(first.value) == "self._assert_not_ui_thread_read"


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


@pytest.mark.parametrize(
    "store_type",
    [TransferSealStore, TransferMemberExchangeStore],
)
def test_transfer_ui_thread_provider_is_one_shot_and_bootstrap_only(
    tmp_path,
    store_type,
):
    ui_thread_id = threading.get_ident()
    first_provider = lambda: ui_thread_id
    different_provider = lambda: ui_thread_id

    # Constructor schema initialization is the sole bootstrap window.  The
    # provider is bound only after it completes, so the window cannot reopen.
    store = store_type(
        tmp_path / f"ui-{store_type.__name__}.db",
        ui_thread_id_provider=first_provider,
    )
    store.bind_ui_thread_id_provider(first_provider)

    with pytest.raises(TransferCoordinatorUiThreadReadError) as raised:
        with store._connect():
            pass
    assert raised.value.code == "TRANSFER_COORDINATOR_UI_THREAD_READ"

    worker_results = []
    worker_errors = []

    def read_on_worker():
        try:
            if isinstance(store, TransferSealStore):
                worker_results.append(store.has_exact_history())
            else:
                worker_results.append(store.blocking_rows())
        except BaseException as exc:  # pragma: no cover - assertion reports it
            worker_errors.append(exc)

    worker = threading.Thread(target=read_on_worker)
    worker.start()
    worker.join(timeout=5.0)
    assert worker.is_alive() is False
    assert worker_errors == []
    assert worker_results in ([False], [[]])

    with pytest.raises(TransferCoordinatorUiThreadBindingError) as rebound:
        store.bind_ui_thread_id_provider(different_provider)
    assert rebound.value.code == "TRANSFER_COORDINATOR_UI_THREAD_REBIND"


@pytest.mark.parametrize(
    ("variant_name", "variant"),
    RUNTIME_UI_READ_VARIANTS,
    ids=[name for name, _variant in RUNTIME_UI_READ_VARIANTS],
)
def test_runtime_ui_read_boundary_is_authoritative_for_tk_root_call_shapes(
    tmp_path,
    monkeypatch,
    variant_name,
    variant,
):
    """Runtime context, not static syntax, rejects all 11 audited + 2 variants."""

    root = _cross_thread_fake_root()
    assert threading.get_ident() == root.owner_thread_id
    ui_provider = lambda: root.owner_thread_id
    store = TransferSealStore(
        tmp_path / f"runtime-{variant_name}.db",
        ui_thread_id_provider=ui_provider,
    )
    coordinator = TransferSealCoordinator(store, None)
    app = ContainerAudit.__new__(ContainerAudit)
    app.root = root
    app.transfer_seal_coordinator = coordinator
    app._svc = SimpleNamespace(store=store)
    monkeypatch.setattr(
        ContainerAudit,
        "_exact_transfer_exchange_blocked",
        variant,
    )

    with pytest.raises(TransferCoordinatorUiThreadReadError) as raised:
        app._exact_transfer_exchange_blocked()

    assert raised.value.code == "TRANSFER_COORDINATOR_UI_THREAD_READ"


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
        ui_thread_id_provider=lambda: root.owner_thread_id,
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
    """Fast static linter only; the runtime UI-read guard is authoritative."""

    root_names = (
        "_update_action_button_states",
        "_show_operations_menu",
        "_exact_transfer_exchange_blocked",
        "_current_transfer_member_exchange_attempt",
        "_precommand_operator_review_retry_context",
        "_transfer_member_exchange_blocks_local_action",
    )
    direct_store_reads = _tk_direct_store_read_paths(
        "Container_Audit.py",
        "ContainerAudit",
        root_names,
    )
    assert direct_store_reads == [], direct_store_reads

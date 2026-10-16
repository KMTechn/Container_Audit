"""Finite AST event inventory; unresolved forwarding sites remain visible."""
import ast
from itertools import product


SINKS = {"_log_event", "_prepare_event_log_entry", "_build_event_log_entry",
         "_log_stored_event", "_checkpoint_audit_event", "_admin_pin_audit",
         "_checkpoint_stored_audit_event", "_log_cancel_event"}
EVENT_KEYS = {"event", "event_type", "event_name"}


def collect_emitters(source, path="<source>"):
    tree = ast.parse(source)
    rows, unresolved = [], []
    partial_names = {"partial"} | {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "functools"
        for alias in node.names if alias.name == "partial"
    }

    def scan(scope, inherited):
        nodes = []
        children = []

        def visit(node):
            nodes.append(node)
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    children.append(child)
                    continue
                visit(child)

        visit(scope)
        values = dict(inherited)
        saturated = set()
        aliases = {name: {(name, frozenset())} for name in SINKS}

        def strings(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return {node.value}
            if isinstance(node, ast.Name):
                return values.get(node.id, set())
            if isinstance(node, ast.Attribute):
                return values.get(node.attr, set())
            if isinstance(node, ast.IfExp):
                return strings(node.body) | strings(node.orelse)
            if isinstance(node, ast.BoolOp):
                return set().union(*(strings(v) for v in node.values))
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                return set().union(*(strings(v) for v in node.elts))
            if isinstance(node, ast.Dict):
                return set().union(*(strings(v) for v in node.values))
            if isinstance(node, ast.Subscript):
                return strings(node.value)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                return {a + b for a, b in product(strings(node.left), strings(node.right))}
            if isinstance(node, ast.JoinedStr):
                parts = [strings(v.value) if isinstance(v, ast.FormattedValue) else strings(v) for v in node.values]
                return {"".join(v) for v in product(*parts)} if all(parts) else set()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "str" and node.args:
                return strings(node.args[0])
            return set()

        def event_arg(call):
            for keyword in call.keywords:
                if keyword.arg in EVENT_KEYS:
                    return strings(keyword.value)
            return strings(call.args[0]) if call.args else set()

        def callable_alias(node):
            if isinstance(node, ast.Attribute) and node.attr in SINKS:
                return {(node.attr, frozenset())}
            if isinstance(node, ast.Name):
                return aliases.get(node.id, set())
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                if name == "getattr" and len(node.args) > 1:
                    return {(v, frozenset()) for v in strings(node.args[1]) if v in SINKS}
                if name in partial_names and node.args:
                    bound = event_arg(ast.Call(func=node.func, args=node.args[1:], keywords=node.keywords))
                    return {(sink, frozenset(set(previous) | bound)) for sink, previous in callable_alias(node.args[0])}
            return set()

        # Union across branches and assignment order, scoped to the enclosing
        # function. No execution, imports, or evaluation of source expressions.
        for _ in range(len(nodes) + 1):
            changed = False
            for node in nodes:
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                expression = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", None)
                    if not name:
                        continue
                    for mapping, found in ((values, strings(expression)), (aliases, callable_alias(expression))):
                        if mapping is values and name in saturated:
                            continue
                        before = mapping.get(name, set())
                        after = before | found
                        if mapping is values and (len(after) > 64 or any(len(v) > 1024 for v in after)):
                            saturated.add(name)
                            after = set()
                        if after != before:
                            mapping[name] = after
                            changed = True
            if not changed:
                break

        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            targets = callable_alias(node.func)
            explicit = set().union(*(strings(k.value) for k in node.keywords if k.arg in EVENT_KEYS))
            if isinstance(node.func, ast.Name) and node.func.id == "_write_paused_status":
                # This writes a relay status JSON; it is not a CSV event emitter.
                explicit = set()
            names = event_arg(node) if targets else explicit
            names |= set().union(*(set(bound) for _, bound in targets))
            item = {"path": path, "line": node.lineno, "scope": getattr(scope, "name", "<module>"),
                    "shape": ast.unparse(node.func)}
            if targets and not names:
                unresolved.append(item | {"expression": ast.unparse(node.args[0]) if node.args else "keyword"})
            for name in sorted(names - {""}):
                rows.append(item | {"event": name})
        for node in children:
            scan(node, values)

    scan(tree, {})
    return rows, unresolved

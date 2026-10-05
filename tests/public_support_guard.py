"""Source-derived field-support sink guard; no source-line allowlist.

Business output is outside contract 0. Generic state/credential serializers are
1a; their diagnostic callers are examined separately. Protected writers are
excluded only at the existing evidence authority, not by redaction alone.
"""
import ast
from pathlib import Path

SUPPORT_PYTHON = frozenset({
    'auto_update.py', 'current_user_onboarding.py', 'container_audit_product_host.py',
    'direct_sync_auto_bootstrap.py', 'direct_sync_operator.py', 'direct_sync_push.py',
    'direct_sync_runtime.py', 'user_relay.py', 'runtime_dependency_guard.py',
    'portable/main.py', 'tools/check_logistics_runtime_profile.py',
    'tools/check_update_archive.py', 'tools/direct_sync_relay_install_pack.py',
    'tools/direct_sync_relay_operator.py', 'tools/direct_sync_relay_runner.py',
    'tools/install_logistics_runtime_profile.py', 'tools/install_protected_admin.py',
    'tools/register_container_audit_worker_pc.py',
})
PUBLIC_BOUNDARIES = frozenset({'public_record', 'support_record'})
COMPUTED_CALLS = frozenset({'len', 'type', 'os.getpid', 'uuid.uuid4',
                          'time.monotonic', 'time.time', 'datetime.now', '_now',
                          'utc_now_text', 'hashlib.sha256'})
PUBLIC_SINKS = frozenset({'print', 'print_exc', 'print_exception', 'showerror',
                         'showwarning', 'showinfo', 'write_text', 'write_bytes',
                         'write', 'dump', 'write_json_durable', '_write_json_atomic',
                         '_write_json_atomic_create_new', '_write_json',
                         '_append_jsonl', '_write_registration_report', 'writer'})
JSON_WRITERS = PUBLIC_SINKS - {'print', 'print_exc', 'print_exception',
                             'showerror', 'showwarning', 'showinfo',
                             'write_text', 'write_bytes', 'write', 'dump'}
# Contract 0 applies to installation/update/support diagnostics. These sources
# contain production scanning/completion UI or build qualification entrypoints;
# their packaging inclusion does not turn those separate flows into support.
OUTSIDE_SUPPORT_FLOW = frozenset({
    'Container_Audit.py', 'replacement_log_lookup.py', 'tray_completion.py',
    'kmtech_factory_contracts/active_work_probe/cli.py',
    'kmtech_factory_contracts/build_cli.py', 'tools/check_release_version.py',
})
STATE_SERIALIZERS = frozenset({
    ('current_user_onboarding.py', '_write_json_atomic'),
    ('current_user_onboarding.py', '_write_json_atomic_create_new'),
    ('container_audit_product_host.py', '_write_json_atomic'),
    ('direct_sync_operator.py', '_write_json_atomic'),
    ('direct_sync_runtime.py', '_write_json_atomic'),
    ('tools/direct_sync_relay_operator.py', '_write_json_atomic'),
    ('tools/register_container_audit_worker_pc.py', '_write_registration_json'),
    ('user_relay.py', '_write_json_atomic'),
})
# These fields are constructed from literal statuses / integer counts by the
# relay producers, not copied from HTTP or configuration strings. The caller
# chains are recorded in REFILTER; no source positions take part in matching.
COMPUTED_RELAY_FIELDS = frozenset({'status', 'scan_status', 'scan_enqueued_count',
    'scan_attempted_count', 'scan_no_new_count', 'scan_terminal_blocked_count'})
RELAY_PRODUCERS = frozenset({'run_relay_once', 'record_scan_status',
    'record_scan_result_status', 'record_scan_drain_status', 'enqueue_completed_source_file'})
ONBOARDING_RESULT_FIELDS = frozenset({'status', 'action', 'bootstrap_integrity'})
ONBOARDING_PRODUCERS = frozenset({'onboard_current_user', 'remove_current_user_setup',
                                'restore_current_user_lifecycle_after_replacement'})


def shipped_sources(root):
    """Read stock declarations and their literal local-import closure."""
    root = Path(root)
    tree = ast.parse((root / 'tools/build_portable_release_candidate.py').read_bytes())
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for name in node.targets:
                if isinstance(name, ast.Name):
                    try:
                        constants[name.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass
    paths = {str(path).replace('\\', '/') for path in constants['APP_ROOT_FILES']}
    paths.add('portable/main.py')
    paths.update(str(item[0]).replace('\\', '/') for item in constants['PORTABLE_INSTALL_ASSETS'])
    for directory in constants['APP_PACKAGE_DIRS']:
        paths.update(p.relative_to(root).as_posix() for p in (root / directory).rglob('*.py'))
    # Frozen field support tools are also shipped, even when stock Python's
    # import closure does not start them. Qualification/build tools are post-cut.
    paths.update(SUPPORT_PYTHON)
    paths.update({'INSTALL_THIS_PC.ps1', 'INSTALL_CANONICAL_PORTABLE.ps1',
                  'tools/bootstrap_integrity.ps1', 'tools/apply_prepared_update.ps1',
                  'tools/container_writer_session.ps1', 'tools/container_writer_fence.ps1',
                  'tools/provision_protected_admin_acl.ps1'})
    visited = set()
    while paths - visited:
        path = next(iter(paths - visited)); visited.add(path)
        source = root / path
        if not source.is_file() or source.suffix != '.py' or path.startswith('vendor/'):
            continue
        for node in ast.walk(ast.parse(source.read_bytes())):
            modules = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
                modules.extend(node.module + '.' + alias.name for alias in node.names)
            for module in modules:
                relative = module.replace('.', '/')
                for candidate in (relative + '.py', relative + '/__init__.py'):
                    if (root / candidate).is_file():
                        paths.add(candidate)
    return sorted(path for path in paths if (root / path).is_file())


def python_candidates(source, filename):
    """Propagate the five provenance sources through local assignments."""
    tree = ast.parse(source)
    parent = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node

    def scope(node):
        while node in parent:
            node = parent[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
        return tree

    assignments, exceptions = {}, {}
    for function in ast.walk(tree):
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for argument in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
                if argument.arg in {'error', 'exc', 'exception'}:
                    exceptions.setdefault(function, {})[argument.arg] = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(scope(node), {}).setdefault(target.id, []).append(node.value)
        if isinstance(node, ast.ExceptHandler) and node.name:
            fixed = isinstance(node.type, ast.Name) and node.type.id == 'DataGenerationBlocked'
            exceptions.setdefault(scope(node), {})[node.name] = 0 if fixed else 1

    normalized_writers = {
        function.name for function in tree.body if isinstance(function, ast.FunctionDef)
        and function.name in JSON_WRITERS
        and any(isinstance(call, ast.Call) and
                ast.unparse(call.func).rsplit('.', 1)[-1] in PUBLIC_BOUNDARIES | {'mixed_status_record'}
                for call in ast.walk(function))
    }

    def provenance(node, bindings, caught, visiting=frozenset()):
        if isinstance(node, ast.Constant):
            return 0
        if isinstance(node, ast.Name):
            if node.id in caught:
                return caught[node.id]
            if node.id in visiting:
                return 0
            values = bindings.get(node.id, [])
            result = 0
            for value in values:
                result |= provenance(value, bindings, caught, visiting | {node.id})
            return result
        if isinstance(node, ast.Attribute):
            if node.attr == 'user_message':
                ancestor = node
                while ancestor in parent:
                    ancestor = parent[ancestor]
                    if isinstance(ancestor, ast.If) and isinstance(ancestor.test, ast.Call):
                        if (ast.unparse(ancestor.test.func) == 'isinstance'
                                and len(ancestor.test.args) == 2
                                and ast.unparse(ancestor.test.args[1]).rsplit('.', 1)[-1] == 'DataGenerationBlocked'):
                            return 0
            if node.attr in {'__name__', '__class__', 'tb_lineno', 'co_name'}:
                return 0
            if node.attr in {'stdout', 'stderr', 'CommandLine'}:
                return 2 if node.attr != 'CommandLine' else 4
            if node.attr in {'argv'}:
                return 4
            if node.attr in {'environ', 'text', 'content'}:
                return 8
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            if (filename == 'current_user_onboarding.py'
                    and node.slice.value in ONBOARDING_RESULT_FIELDS
                    and isinstance(node.value, ast.Name)):
                producers = {ast.unparse(value.func).rsplit('.', 1)[-1]
                             for value in bindings.get(node.value.id, []) if isinstance(value, ast.Call)}
                if producers & ONBOARDING_PRODUCERS:
                    return 0
            if (filename == 'tools/direct_sync_relay_runner.py'
                    and node.slice.value in COMPUTED_RELAY_FIELDS
                    and isinstance(node.value, ast.Name)
                    and node.value.id in {'status', 'preflight_status'}):
                producers = {ast.unparse(value.func).rsplit('.', 1)[-1]
                             for value in bindings.get(node.value.id, []) if isinstance(value, ast.Call)}
                if producers & RELAY_PRODUCERS:
                    return 0
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func)
            leaf = name.rsplit('.', 1)[-1]
            if leaf in PUBLIC_BOUNDARIES or name in COMPUTED_CALLS:
                return 0
            if leaf == 'mixed_status_record':
                # Existing mixed schemas are tested separately against their
                # exact machine consumers; diagnostic leaves alone are coded.
                return 0
            if filename == 'current_user_onboarding.py' and leaf == 'preflight_current_user_onboarding':
                # Returns only SHA256 / SHA256:SHA256; canonical parser checks
                # exactly those two forms before any mutation.
                return 0
            if filename == 'auto_update.py' and leaf in {'install_task_spec', 'resolve_lifecycle_context'}:
                # Machine protocols consumed by INSTALL_THIS_PC:1117/2089-2151,
                # not human diagnostics; exception diagnostics use the mapper.
                return 0
            if leaf in {'format_exception', 'format_exc', 'print_exc', 'print_exception'}:
                return 1
            if leaf in {'_failure_details', 'failure_details'}:
                return 1
            if leaf in {'input', 'getenv', 'read_json', '_read_json', 'read_text', 'getresponse', 'json'}:
                return 8
            if leaf in {'parse_args', 'parse_known_args'}:
                return 4
            if leaf in {'hexdigest', 'isoformat', 'strftime'}:
                return 0
        result = 0
        for child in ast.iter_child_nodes(node):
            result |= provenance(child, bindings, caught, visiting)
        return result

    result = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        leaf = ast.unparse(node.func).rsplit('.', 1)[-1]
        owner = scope(node)
        owner_name = owner.name if isinstance(owner, ast.FunctionDef) else '<module>'
        if leaf in {'parse_args', 'parse_known_args'}:
            parser_name = node.func.value.id if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) else ''
            bindings = assignments.get(owner, {})
            constructors = [ast.unparse(value.func).rsplit('.', 1)[-1]
                            for value in bindings.get(parser_name, []) if isinstance(value, ast.Call)]
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
                constructors.append(ast.unparse(node.func.value.func).rsplit('.', 1)[-1])
            safe_builder = any(isinstance(function, ast.FunctionDef) and function.name == 'build_parser'
                               and any(isinstance(call, ast.Call) and ast.unparse(call.func).rsplit('.', 1)[-1]
                                       == 'SupportArgumentParser' for call in ast.walk(function))
                               for function in tree.body)
            if 'SupportArgumentParser' in constructors or ('build_parser' in constructors and safe_builder):
                continue
            result.append({'file': filename, 'function': owner_name, 'line': node.lineno,
                           'sink': leaf, 'sources': 4})
            continue
        if leaf not in PUBLIC_SINKS:
            continue
        if leaf in normalized_writers:
            # Inspect the mapper's actual write below; its callers are inputs,
            # rather than additional file-publication boundaries.
            continue
        bindings = dict(assignments.get(tree, {})); bindings.update(assignments.get(owner, {}))
        caught = exceptions.get(owner, {})
        # A name such as "exc" can be reused in several handlers. Its origin
        # is the enclosing handler at this sink, not the last handler in a file.
        ancestor = node
        while ancestor in parent:
            ancestor = parent[ancestor]
            if isinstance(ancestor, ast.ExceptHandler):
                if ancestor.name:
                    fixed = (ancestor.type is not None and ast.unparse(ancestor.type).rsplit('.', 1)[-1]
                             == 'DataGenerationBlocked')
                    caught = {**caught, ancestor.name: 0 if fixed else 1}
                break
        causes = 1 if leaf in {'print_exc', 'print_exception'} else 0
        arguments = node.args[1:] if leaf in JSON_WRITERS else node.args[:1] if leaf == 'dump' else node.args
        for argument in arguments:
            causes |= provenance(argument, bindings, caught)
        if causes:
            result.append({'file': filename, 'function': owner_name, 'line': node.lineno,
                           'sink': leaf, 'sources': causes})
    return result

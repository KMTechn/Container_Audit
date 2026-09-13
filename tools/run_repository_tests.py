"""Run repository tests with owned state and durable, bounded evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def _repository_state(root: Path, env: dict[str, str]) -> tuple[str, set[str]]:
    status = subprocess.run(
        ['git', 'status', '--porcelain=v1', '--untracked-files=all'],
        cwd=root, env=env, capture_output=True, text=True, check=True,
    ).stdout
    ignored = subprocess.run(
        ['git', 'ls-files', '--others', '--ignored', '--exclude-standard', '-z'],
        cwd=root, env=env, capture_output=True, text=True, check=True,
    ).stdout
    return status, set(ignored.split('\0')) - {''}


def main() -> int:
    sys.dont_write_bytecode = True
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--task-root', '--work-root', dest='task_root', type=Path,
        default=Path(os.environ.get('CONTAINER_AUDIT_TEST_TASK_ROOT')
                     or 'D:/KMTech/test-runs/Container_Audit'),
        help='Parent for a unique run (env: CONTAINER_AUDIT_TEST_TASK_ROOT; --work-root is an alias)',
    )
    args, pytest_args = parser.parse_known_args()
    task_root = args.task_root.resolve()
    if task_root.is_relative_to(root) or root.is_relative_to(task_root):
        parser.error('test task root must be outside, and must not contain, the repository')
    run = task_root / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    run.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
               PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTHONUTF8='1', GIT_OPTIONAL_LOCKS='0')
    for name in ('PYTEST_ADDOPTS', 'PYTEST_PLUGINS', 'KMTECH_TEST_CA_WRITER_ROOT',
                 'KMTECH_TEST_CA_WRITER_MUTEX', 'KMTECH_TEST_CA_SITECUSTOMIZE_MARKER'):
        env.pop(name, None)
    env['PYTHONPATH'] = os.pathsep.join((str(root / 'tests'), str(root)))
    env['KMTECH_TEST_CA_TASK_ROOT'] = str(run)
    env['CONTAINER_AUDIT_DATA_ROOT'] = str(run / 'data')
    env['CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH'] = str(run / 'data/logistics-profile/runtime-profile.json')
    env['KM_LOGISTICS_PROFILE_PATH'] = env['CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH']
    for name in ('TEMP', 'TMP', 'LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA'):
        owned = run / name.lower()
        owned.mkdir()
        env[name] = str(owned)
    if os.name == 'nt':
        env['PSModulePath'] = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')
    env['PSModuleAnalysisCachePath'] = str(run / 'module-cache')
    os.environ.update(env)
    for name in ('PYTEST_ADDOPTS', 'PYTEST_PLUGINS', 'KMTECH_TEST_CA_WRITER_ROOT',
                 'KMTECH_TEST_CA_WRITER_MUTEX', 'KMTECH_TEST_CA_SITECUSTOMIZE_MARKER'):
        os.environ.pop(name, None)
    sys.path.insert(0, str(root))
    from tests.sitecustomize import install_write_boundary
    install_write_boundary()
    before = _repository_state(root, env)
    command = [sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
               *(pytest_args or ['tests']),
               '--basetemp', str(run / 'p'), '--junitxml', str(run / 'junit.xml')]
    started = time.monotonic()
    with (run / 'stdout.txt').open('xb') as stdout, (run / 'stderr.txt').open('xb') as stderr:
        process = subprocess.run(command, cwd=root, env=env, stdout=stdout, stderr=stderr,
                                 check=False)
    after = _repository_state(root, env)
    violations = run / 'boundary-violations.jsonl'
    boundary_count = len(violations.read_text(encoding='utf-8').splitlines()) if violations.exists() else 0
    exit_code = process.returncode or int(before != after or boundary_count > 0)
    result = {'command': command, 'exit_code': exit_code,
              'pytest_exit_code': process.returncode,
              'repository_unchanged': before == after, 'repository_clean': not after[0],
              'new_ignored_artifacts': sorted(after[1] - before[1]),
              'outside_write_attempts': boundary_count,
              'wall_seconds': round(time.monotonic() - started, 3),
              'stderr_bytes': (run / 'stderr.txt').stat().st_size, 'evidence_path': str(run)}
    (run / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'command'}))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())

"""Run repository tests with owned state and durable, bounded evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid


DEFAULT_TASK_ROOT = Path('D:/KMTech/t/ca')
PATH_BUDGET = 240  # Operational headroom, not a guarantee for every Win32 API.


def _longest_candidate(run: Path) -> Path:
    # conftest.tmp_path: ten hex digits plus pytest's first numbered suffix.
    fixture = run / 'p' / ('f' * 10 + '0')
    candidates = [
        # canonical_portable_uninstall._setup + container_writer_fence.ps1 receipt.
        fixture / 'LOCALAPPDATA/KMTech/DirectSync/container_audit/control/writer-session'
        / ('release-' + 'f' * 32 + '-' + 'f' * 64 + '.json'),
        # zero_touch_installer._portable_release_fixture, bootstrap staging copy.
        fixture / 'apps' / ('.current.bootstrap.' + 'f' * 32)
        / 'tools/container_writer_session_contract.json',
        # kmtech_shared standalone child pytest, copied package drift fixtures.
        fixture / 'child-pytest' / ('f' * 10 + '0')
        / 'kmtech_shared/powershell/portable.ps1',
        run / 'data/logistics-profile/runtime-profile.json',
    ]
    return max(candidates, key=_path_length)


def _path_length(path: Path) -> int:
    return len(str(path).encode('utf-16-le')) // 2


def _source_state(root: Path, env: dict[str, str], status: str) -> dict:
    def git(*args):
        return subprocess.run(['git', *args], cwd=root, env=env,
                              capture_output=True, check=True).stdout

    # Hash bytes, never include diff contents in evidence (they may be sensitive).
    names = git('ls-files', '--cached', '--others', '--exclude-standard', '-z',
                '--', '*.py', '*.ps1', '*.json', '*.ini', '*.toml', '*.cfg')
    fingerprints = {}
    for name in sorted(set(os.fsdecode(names).split('\0')) - {''}):
        path = root / name
        if path.is_file():
            with path.open('rb') as stream:
                fingerprints[name] = hashlib.file_digest(stream, 'sha256').hexdigest()
        else:
            fingerprints[name] = None
    return {'head_sha': git('rev-parse', 'HEAD').decode().strip(),
            'dirty': bool(status), 'status': status.splitlines(),
            'diff_sha256': hashlib.sha256(git('diff', '--binary', 'HEAD')).hexdigest(),
            'file_sha256': fingerprints}


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
                     or DEFAULT_TASK_ROOT),
        help='Parent for a unique run (env: CONTAINER_AUDIT_TEST_TASK_ROOT; --work-root is an alias)',
    )
    args, pytest_args = parser.parse_known_args()
    task_root = args.task_root.resolve()
    if task_root.is_relative_to(root) or root.is_relative_to(task_root):
        parser.error('test task root must be outside, and must not contain, the repository')
    run = task_root / uuid.uuid4().hex[:8]
    longest = _longest_candidate(run)
    if _path_length(longest) > PATH_BUDGET:
        parser.error(f'longest fixture path is {_path_length(longest)} UTF-16 units '
                     f'(budget {PATH_BUDGET}): {longest}; '
                     'use a shorter --task-root D:\\KMTech\\t\\ca')
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
        owned = run / ('t' if name in ('TEMP', 'TMP') else name.lower())
        owned.mkdir(exist_ok=True)
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
    source_before = _source_state(root, env, before[0])
    powershell_version = None
    if os.name == 'nt':
        powershell_version = subprocess.run(
            [str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'),
             '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()'],
            env=env, capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
    command = [sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
               *(pytest_args or ['tests']),
               '--basetemp', str(run / 'p'), '--junitxml', str(run / 'junit.xml')]
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    with (run / 'stdout.txt').open('xb') as stdout, (run / 'stderr.txt').open('xb') as stderr:
        process = subprocess.run(command, cwd=root, env=env, stdout=stdout, stderr=stderr,
                                 check=False)
    finished_at = datetime.now(timezone.utc).isoformat()
    after = _repository_state(root, env)
    source_after = _source_state(root, env, after[0])
    source_stable = source_before == source_after
    violations = run / 'boundary-violations.jsonl'
    boundary_count = len(violations.read_text(encoding='utf-8').splitlines()) if violations.exists() else 0
    exit_code = process.returncode or int(before != after or not source_stable or boundary_count > 0)
    result = {'command': command, 'exit_code': exit_code,
              'pytest_exit_code': process.returncode,
              'repository_unchanged': before == after and source_stable, 'repository_clean': not after[0],
              'new_ignored_artifacts': sorted(after[1] - before[1]),
              'outside_write_attempts': boundary_count,
              'run_id': run.name, 'started_at_utc': started_at, 'finished_at_utc': finished_at,
              'source_before': source_before, 'source_after': source_after,
              'source_stable': source_stable,
              'evidence_status': 'UNPROVEN' if not source_stable else ('FAIL' if exit_code else 'PASS'),
              'python_version': sys.version, 'powershell_version': powershell_version,
              'task_drive': run.drive,
              'basetemp': str(run / 'p'), 'basetemp_drive': (run / 'p').drive,
              'longest_candidate_path': str(longest),
              'longest_candidate_length': _path_length(longest), 'path_budget': PATH_BUDGET,
              'wall_seconds': round(time.monotonic() - started, 3),
              'stderr_bytes': (run / 'stderr.txt').stat().st_size, 'evidence_path': str(run)}
    (run / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('command', 'source_before', 'source_after')}
                     | {'head_sha': source_before['head_sha'], 'dirty': source_before['dirty']}))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())

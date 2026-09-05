"""Run repository tests with owned state and durable, bounded evidence."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-root', type=Path, default=root / '.test-runs')
    args, pytest_args = parser.parse_known_args()
    run = args.work_root.resolve() / uuid.uuid4().hex[:10]
    run.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
               PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    env.pop('CONTAINER_AUDIT_DATA_ROOT', None)
    for name in ('TEMP', 'TMP', 'LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA'):
        owned = run / name.lower()
        owned.mkdir()
        env[name] = str(owned)
    if os.name == 'nt':
        env['PSModulePath'] = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')
    env['PSModuleAnalysisCachePath'] = str(run / 'module-cache')
    command = [sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
               '--basetemp', str(run / 'p'), '--junitxml', str(run / 'junit.xml'),
               *(pytest_args or ['tests'])]
    started = time.monotonic()
    with (run / 'stdout.txt').open('xb') as stdout, (run / 'stderr.txt').open('xb') as stderr:
        process = subprocess.run(command, cwd=root, env=env, stdout=stdout, stderr=stderr,
                                 check=False)
    result = {'command': command, 'exit_code': process.returncode,
              'wall_seconds': round(time.monotonic() - started, 3),
              'stderr_bytes': (run / 'stderr.txt').stat().st_size, 'evidence_path': str(run)}
    (run / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'command'}))
    return process.returncode


if __name__ == '__main__':
    raise SystemExit(main())

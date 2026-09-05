"""Owned real relay processes for onboarding lifecycle integration tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from user_relay import request_user_relay_stop, user_relay_status_path, user_relay_stop_path

ROOT = Path(__file__).resolve().parents[1]


class OwnedRelay:
    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.children = []

    def start(self, direct_sync_root, *, wait_for_running=True):
        root = Path(direct_sync_root)
        assert not user_relay_stop_path(root).exists(), 'launch must follow stop-marker removal'
        status_path = user_relay_status_path(root)
        status_path.unlink(missing_ok=True)
        command = [sys.executable, '-B', '-c',
                   'import sys, user_relay; raise SystemExit(user_relay.main(sys.argv[1:]))',
                   '--app-root', str(ROOT),
                   '--direct-sync-root', str(root), '--scan-source-dir', str(self.tmp_path/'empty-events')]
        prefix = self.tmp_path / f'lifecycle-child-{len(self.children)}'
        with prefix.with_suffix('.stdout').open('xb') as stdout, prefix.with_suffix('.stderr').open('xb') as stderr:
            process = subprocess.Popen(command, cwd=ROOT, stdout=stdout, stderr=stderr,
                                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.children.append((root, process))
        if not wait_for_running:
            return {'status': 'START_REQUESTED', 'process_id': process.pid}
        self.wait_running(root, process)
        return {'status': 'START_REQUESTED', 'process_id': process.pid}

    def wait_running(self, root, process):
        status_path = user_relay_status_path(root)
        deadline = time.monotonic() + 15
        while process.poll() is None and time.monotonic() < deadline:
            if status_path.exists():
                status = json.loads(status_path.read_text(encoding='utf-8'))
                if status['status'] == 'RUNNING':
                    return
            time.sleep(.025)
        raise AssertionError(f'owned production relay did not become RUNNING; exit={process.poll()}')

    def stop(self, direct_sync_root):
        result = request_user_relay_stop(direct_sync_root, timeout_seconds=10)
        assert result['status'] == 'ABSENT', 'real runtime-instance absence was not proven'
        return result

    def wait_stopped(self, direct_sync_root):
        for root, process in self.children:
            if root == Path(direct_sync_root):
                process.wait(timeout=10)

    def finish(self):
        for root, process in self.children:
            if process.poll() is None:
                try:
                    self.stop(root)
                    self.wait_stopped(root)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)


@pytest.fixture
def owned_relay(tmp_path):
    if os.name != 'nt':
        pytest.skip('real relay absence proof requires the Windows runtime mutex')
    relay = OwnedRelay(tmp_path)
    try:
        yield relay
    finally:
        relay.finish()

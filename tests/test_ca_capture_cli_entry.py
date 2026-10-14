from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_capture_cli_help_without_inherited_repository_path(tmp_path):
    # -I removes the parent's PYTHONPATH; iwrun2 admits only this exact CLI.
    result = subprocess.run(
        [sys.executable, '-I', '-B', str(ROOT / 'tools/capture_container_operator_ui.py'), '--help'],
        cwd=str(ROOT), capture_output=True, timeout=30,
    )
    import json
    (tmp_path / 'cli-result.json').write_text(json.dumps({
        'exit_code': result.returncode,
        'module_not_found': b'ModuleNotFoundError' in result.stderr,
        'has_usage': b'usage:' in result.stdout,
    }), encoding='utf-8')
    assert result.returncode == 0
    assert b'usage:' in result.stdout
    assert b'ModuleNotFoundError' not in result.stderr


def test_iwrun_evidence_exception_keeps_unrelated_writes_denied(tmp_path, monkeypatch):
    import contextlib
    import io
    import os
    import uuid
    import pytest
    import tests.sitecustomize as boundary
    root = Path(os.environ['KMTECH_TEST_CA_TASK_ROOT']).resolve()
    target = root.parent / ('ca-unadmitted-' + uuid.uuid4().hex + '.txt')
    assert not target.exists()
    guards = []
    monkeypatch.setattr(sys, '_kmtech_ca_write_boundary', False)
    monkeypatch.setattr(sys, 'addaudithook', guards.append)
    boundary.install_write_boundary()
    assert len(guards) == 1
    # Exercise the exact guard without adding an expected denial to the live
    # session's incident log (which correctly fails that entire session).
    denial = io.StringIO()
    original_open = Path.open
    def captured_denial(path, *args, **kwargs):
        if path.parent == root:
            return contextlib.nullcontext(denial)
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', captured_denial)
    with pytest.raises(AssertionError):
        guards[0]('open', (str(target), 'w', os.O_WRONLY | os.O_CREAT))
    guards[0]('open', (str(tmp_path / 'permitted.txt'), 'w', os.O_WRONLY | os.O_CREAT))
    assert denial.getvalue()
    assert not target.exists()

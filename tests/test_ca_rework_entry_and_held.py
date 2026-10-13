"""Exercise the deployed entry and bounded held list without product windows."""
from pathlib import Path
from types import SimpleNamespace
import json
import shutil
import subprocess

import pytest

import ca_screen_bridge as screen
from preflight_scan_hold import PreflightHoldSnapshot, QuarantinedPreflightHold, HOLD_LOOKUP, HOLD_LOOKUP_FAILED
from tests.test_ca_screen_bridge import _app, _schema_errors
from tests.test_w9scanonly_workflow import flow, windows, fixed_operation_lease_clock, COMPACT_QR

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.usefixtures('fixed_operation_lease_clock', 'windows', 'owned_tk_workers')



@pytest.mark.parametrize('normal_count,hold_states', (
    (49, (HOLD_LOOKUP_FAILED,)), (50, (HOLD_LOOKUP_FAILED,)),
    (49, (HOLD_LOOKUP,)), (50, (HOLD_LOOKUP,)),
    (48, (HOLD_LOOKUP_FAILED, HOLD_LOOKUP)), (49, (HOLD_LOOKUP_FAILED, HOLD_LOOKUP)),
    (50, ()), (51, ()), (0, (HOLD_LOOKUP_FAILED,) * 50 + (HOLD_LOOKUP,)),
))
def test_held_overflow_preserves_total_and_each_restricted_kind(flow, tmp_path, normal_count, hold_states):
    app = _app(flow)
    entries = [SimpleNamespace(path=tmp_path / f'normal-{i}.json', scan_count=i, item_name='synthetic')
               for i in range(normal_count)]
    holds = [QuarantinedPreflightHold(tmp_path / f'hold-{i}.json',
             PreflightHoldSnapshot('synthetic-hold', 1, app.worker_name, COMPACT_QR, '', '', state, (),
                                   'PHS2_PREFLIGHT_UNAVAILABLE'), '') for i, state in enumerate(hold_states)]
    app._parked_store = lambda: SimpleNamespace(scan_for_worker=lambda *a, **k: entries)
    app._quarantined_preflight_holds = lambda: tuple(holds)
    total = normal_count + len(holds)
    app.parked_tree = SimpleNamespace(get_children=lambda: tuple(range(total)))
    writes = []
    app.restore_parked_tray = lambda path: writes.append(path)
    processor = screen.CaProcessor(app)
    assert processor.state()['held_count'] == total
    processor.command('open', {'id': 'held'})
    state = processor.state()
    assert state['held_count'] == total
    assert len(state['park']) == min(50, total)
    assert state['overflow'] is (total > 50)
    expected_kinds = {'server_wait' if value == HOLD_LOOKUP else 'quarantine' for value in hold_states}
    shown = [row for row in state['park'] if row.get('restorable') is False]
    assert {row['kind'] for row in shown} == expected_kinds
    assert len(shown) == min(50, len(holds))
    assert _schema_errors(state, screen.json.loads(screen.CONTRACT.read_bytes())['state']) == []
    for row in shown:
        assert processor.command('restore', {'id': row['id']})['ok'] is False
    assert writes == []


@pytest.mark.parametrize('total', (50, 51))
def test_held_ui_shows_total_and_overflow_without_browser(total):
    source = (ROOT / 'ui/app/ca/ca.js').read_text(encoding='utf-8')
    function = source[source.index('  function renderHeld(s)'):source.index('  function drawTray(')]
    state = {'park': [{'restorable': False, 'label': 'synthetic', 'note': 'synthetic'}] * 50,
             'held_count': total, 'overflow': total > 50,
             'today': {'total_trays': 0, 'rows': [], 'supply': 0},
             'work': {'count': 0, 'item': None}}
    script = r'''
const assert = require('node:assert/strict');
const nodes = {};
const el = (tag, cls, text = '') => ({tag, cls, textContent: text, children: [],
  append(...children) { this.children.push(...children); },
  replaceChildren(...children) { this.children = children; }});
const $ = (selector) => nodes[selector] ||= el('container', '');
const drawTray = () => {};
''' + function + '\nrenderHeld(' + json.dumps(state) + ');\n' + r'''
assert.equal(nodes['[data-park-title]'].textContent, '보류 작업 · TOTAL건'.replace('TOTAL', String(TOTAL)));
const children = nodes['[data-park]'].children;
assert.equal(children.length, TOTAL > 50 ? 51 : 50);
if (TOTAL > 50) {
  assert.ok(children[50].textContent.includes('전체 51건 중 50건 표시'));
  assert.ok(children[50].textContent.includes('옛 화면'));
}
console.log('HELD_OVERFLOW_PASS');
'''.replace('TOTAL', str(total))
    node = shutil.which('node')
    assert node is not None
    result = subprocess.run([node, '-e', script], capture_output=True, text=True,
                            encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'HELD_OVERFLOW_PASS'

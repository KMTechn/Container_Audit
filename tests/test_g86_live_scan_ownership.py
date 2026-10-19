"""Live input ownership across two scans in one real shell pump."""
import queue
import threading
from concurrent.futures import Future
from types import SimpleNamespace as NS

from tests import test_g86_scan_input_ownership as g
from tests.test_g86_review_scan_ownership import bridge_for, feedback


SHELL = g.methods('shell/bridge.py',
    {'pump', '_dispatch', '_expire_pending', '_process_scan', '_processor_scan'},
    {'queue': queue, 'threading': threading})


def shell_for(processor):
    shell = type('ShellOwner', (), SHELL)()
    shell.owner_thread_id = threading.get_ident()
    shell._owner_done = False
    shell._tasks, shell._pending = queue.Queue(), {}
    shell._next_seq, shell._last_seq = 1, 0
    shell._delay_ms, shell._failed = 0, False
    shell._processor, shell.profile, shell.src = processor, 'transfer', 'test'
    shell.receipts, shell.sounds = [], []
    shell.journal = NS(append=shell.receipts.append)
    shell.events = NS(record=lambda *args, **kwargs: None)
    shell._play = lambda seq, sound: shell.sounds.append(sound)
    shell._remember_result = lambda seq, reply: None
    shell._snapshot = lambda: {}
    shell.push = lambda reply: None
    return shell


def enqueue(shell, raw, seq):
    future = Future()
    meta = {'seq': seq, 'evidence': {'pedal_pressed': True}}
    shell._tasks.put_nowait(('scan', (raw, meta, 0, (False, 0)), future))
    return future


def test_same_shell_pump_preserves_first_scan_and_visibly_rejects_second():
    app = g.ca_app()
    notices, sounds = feedback(app)
    shell = shell_for(bridge_for(app))
    first = enqueue(shell, g.FIRST, 1)
    second = enqueue(shell, g.SECOND, 2)

    assert shell.pump()
    assert first.result(timeout=0)['accepted'] is True
    assert second.result(timeout=0)['accepted'] is False
    assert second.result(timeout=0)['message']
    assert notices and sounds
    assert app.scan_entry.get() == g.FIRST
    assert app._scan_callback_pending and app.accepted == []
    assert len(shell.receipts) == 1

    app.root.drain()
    assert app.accepted == [g.FIRST]
    assert len(app.accepted) == 1
    assert app.scan_entry.get() == ''
    assert g.SECOND not in app.accepted

    retry = enqueue(shell, g.SECOND, 3)
    assert shell.pump()
    assert retry.result(timeout=0)['accepted'] is True
    app.root.drain()
    assert app.accepted == [g.FIRST, g.SECOND]


def test_bridge_preserves_live_preflight_append_until_ack():
    app = g.ca_app()
    notices, sounds = feedback(app)
    app._master_preflight_pending = True
    callbacks = []
    app._preflight_hold_writer = lambda: NS(submit=lambda work, finish, fail:
        (callbacks.append(finish), NS(accepted=True))[1])
    bridge = bridge_for(app)
    assert bridge.scan(g.FIRST, {})['accepted'] is True
    assert app._preflight_hold_append_pending
    response = bridge.scan(g.SECOND, {})
    assert response['accepted'] is False and response['message']
    assert notices and sounds
    assert app.scan_entry.get() == g.FIRST
    assert app._preflight_hold_append_pending and len(callbacks) == 1
    assert app.accepted == []
    callbacks[0]((None, NS(items=[g.FIRST])))
    assert app.scan_entry.get() == ''
    assert app._preflight_hold_snapshot.items == [g.FIRST]
    app._master_preflight_pending = False
    assert bridge.scan(g.SECOND, {})['accepted'] is True
    app.root.drain()
    assert app.accepted == [g.SECOND]

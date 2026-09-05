"""Loopback transport for independently captured server contracts."""
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from urllib.parse import urlsplit

import requests


def load_contract(name):
    root = Path(__file__).parent
    provenance = json.loads((root / 'provenance.json').read_text(encoding='utf-8'))
    raw = (root / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == provenance['outputs'][name]
    return json.loads(raw)


@contextmanager
def replay_server(records):
    pending = list(records)
    observed = []
    errors = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            try:
                assert pending, 'unexpected extra request'
                expected = pending.pop(0)
                assert self.command == expected['method'], 'request method differs'
                assert self.path == expected['path'], 'request endpoint differs'
                assert (json.loads(body) if body else None) == expected['body'], 'request body differs'
                for name, value in expected['headers'].items():
                    assert self.headers.get(name) == value, 'request header differs: ' + name
                observed.append(self.command)
                payload = expected['response']
                status = expected['status_code']
            except (AssertionError, ValueError) as exc:
                errors.append(str(exc))
                payload = {'ok': False, 'error': {'code': 'CONTRACT_MISMATCH'}}
                status = 500
            encoded = json.dumps(payload).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        do_GET = respond
        do_POST = respond

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    session = requests.Session()
    session.trust_env = False

    class LocalSession:
        def request(self, method, url, **kwargs):
            parsed = urlsplit(url)
            assert parsed.netloc == 'logistics.test.invalid'
            local_url = f'http://127.0.0.1:{server.server_port}{parsed.path}'
            if parsed.query:
                local_url += '?' + parsed.query
            return session.request(method, local_url, **kwargs)

    thread.start()
    try:
        yield LocalSession(), observed
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), 'owned HTTP server did not stop'
        assert not errors, '; '.join(errors)
        assert not pending, 'expected request sequence was incomplete'

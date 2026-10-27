"""Publication refusal is local to diagnostics, with atomic marker/count writes."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest
import auto_update
import atomic_replace
from tools import direct_sync_relay_install_pack as pack
from report_publication import failure_count, UNAVAILABLE


@pytest.mark.parametrize('scene', ['late-marker', 'replacement-marker', 'json-number'])
def test_strict_redactor_rejects_but_report_publishes_marker(tmp_path, monkeypatch, scene):
    environment = {'KMTECH_TEST_API_TOKEN': 'REDACTED' if scene == 'replacement-marker' else 'KMTECH_TEST_SHORT' if scene == 'late-marker' else '4826'}
    if scene == 'late-marker':
        environment['KMTECH_TEST_SHORT_PASSWORD'] = 'x'
    raw_text = auto_update.redact_for_sink
    raw_json = auto_update.redact_json_for_sink
    monkeypatch.setattr(auto_update, 'redact_for_sink', lambda text, environ=None, **kwargs: raw_text(text, environment if environ is None else environ, **kwargs))
    monkeypatch.setattr(auto_update, 'redact_json_for_sink', lambda value, environ=environment: raw_json(value, environ))
    payload = {'detail': 4826} if scene == 'json-number' else {'label': 'REDACTED' if scene == 'replacement-marker' else 'public'}
    with pytest.raises(ValueError, match='^REPORT_UNAVAILABLE$') as captured:
        auto_update.serialize_json_for_sink(payload)
    functions = []
    frame = captured.value.__traceback__
    while frame is not None:
        functions.append(frame.tb_frame.f_code.co_name)
        frame = frame.tb_next
    assert ('_assert_final_known_values' if scene == 'late-marker' else '_redact_known_values' if scene == 'replacement-marker' else 'serialize_json_for_sink') in functions
    path = tmp_path / 'report.json'
    pack._write_json(path, payload)
    decoded = json.loads(path.read_bytes())
    assert decoded == {'report_status': 'REPORT_UNAVAILABLE', 'message': UNAVAILABLE}
    raw = path.read_text(encoding='utf-8')
    assert all(name not in raw and (len(value) < 4 or value not in raw) for name, value in environment.items())
    assert failure_count(path) == 1
    assert json.loads(next(tmp_path.glob('.report-unavailable-count.json')).read_bytes()) == {'count': 1}


def test_concurrent_failures_keep_both_markers_and_count_two(tmp_path, monkeypatch):
    def unavailable(payload):
        raise ValueError('REPORT_UNAVAILABLE')
    monkeypatch.setattr(auto_update, 'serialize_json_for_sink', unavailable)
    paths = [tmp_path / 'first.json', tmp_path / 'second.json']
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda path: pack._write_json(path, {'message': 'public'}), paths))
    assert all(json.loads(path.read_bytes())['message'] == UNAVAILABLE for path in paths)
    assert failure_count(paths[0]) == 2
    assert json.loads(next(tmp_path.glob('.report-unavailable-count.json')).read_bytes()) == {'count': 2}


def test_marker_write_failure_keeps_old_complete_report(tmp_path, monkeypatch):
    path = tmp_path / 'report.json'
    before = b'{"old":1}\n'
    path.write_bytes(before)
    def unavailable(payload):
        raise ValueError('REPORT_UNAVAILABLE')
    monkeypatch.setattr(auto_update, 'serialize_json_for_sink', unavailable)
    original = atomic_replace.atomic_replace
    def interrupted(source, target, **kwargs):
        if Path(target) == path:
            raise OSError('synthetic publication interruption')
        return original(source, target, **kwargs)
    monkeypatch.setattr(atomic_replace, 'atomic_replace', interrupted)
    pack._write_json(path, {'message': 'public'})
    assert path.read_bytes() == before
    assert not list(tmp_path.glob('report.json.tmp.*'))
    assert failure_count(path) == 1


def test_unknown_serialization_failure_keeps_original_error_and_file(tmp_path, monkeypatch):
    path = tmp_path / 'report.json'
    before = b'{"old":1}\n'
    path.write_bytes(before)
    def invalid(payload):
        raise ValueError('unrelated serialization failure')
    monkeypatch.setattr(auto_update, 'serialize_json_for_sink', invalid)
    with pytest.raises(ValueError):
        pack._write_json(path, {'message': 'public'})
    assert path.read_bytes() == before
    assert failure_count(path) == 0

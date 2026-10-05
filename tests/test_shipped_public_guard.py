"""Static additions must be detected from syntax/provenance, not line numbers."""
from pathlib import Path

from tests.public_support_guard import (OUTSIDE_SUPPORT_FLOW, SUPPORT_PYTHON,
                                       python_candidates, shipped_sources)

ROOT = Path(__file__).resolve().parents[1]


def test_shipped_support_python_has_no_five_source_public_output():
    shipped = shipped_sources(ROOT)
    assert SUPPORT_PYTHON <= set(shipped)
    remaining = []
    for source in shipped:
        if source.endswith('.py') and source not in OUTSIDE_SUPPORT_FLOW:
            remaining.extend(python_candidates((ROOT / source).read_bytes(), source))
    assert not remaining, [(item['file'], item['function'], item['line'], item['sources'])
                           for item in remaining]


def test_new_exception_sentence_is_red_without_inventory_line_entry():
    source = '''
def newly_added_support_path():
    try:
        raise ValueError('synthetic')
    except Exception as error:
        sentence = 'failure: ' + str(error)
        print(sentence)
'''
    found = python_candidates(source, 'tools/new_support.py')
    assert len(found) == 1 and found[0]['sources'] == 1


def test_new_child_external_and_argument_outputs_are_detected():
    source = '''
import argparse
import subprocess
def support_path():
    child = subprocess.run(['approved-child'], capture_output=True)
    print(child.stderr)
    answer = input('fixed prompt')
    print(answer)
    print(int(input('fixed prompt')))
    _write_json(Path('new-report.json'), {'error_message': input('fixed prompt')})
    parser = argparse.ArgumentParser()
    parser.parse_args()
    try:
        raise ValueError('synthetic')
    except Exception as error:
        Path('new-report.json').write_text(str(error))
'''
    found = python_candidates(source, 'tools/new_support.py')
    assert {item['sources'] for item in found} == {1, 2, 4, 8}
    assert sum(item['sources'] == 8 for item in found) == 3


def test_computed_type_count_and_validated_record_are_registered():
    source = '''
def support_path():
    try:
        raise ValueError('synthetic')
    except Exception as error:
        print(type(error).__name__)
        print(len(str(error)))
        record = public_record({'error_message': str(error)}, CODES, MESSAGES)
        print(record)
'''
    assert python_candidates(source, 'tools/new_support.py') == []

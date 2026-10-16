"""Only the three RECORD-bound pythonnet runtime files may cross the denylist."""
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

import pytest

import update_service as service
from test_runtime_file_inventory import POLICY, packet


PREFIX = 'Container_Audit/app/site-packages/'
RUNTIME = PREFIX + 'pythonnet/runtime/'
NAMES = ('Python.Runtime.dll', 'Python.Runtime.deps.json', 'Python.Runtime.xml')
RECORD = PREFIX + 'pythonnet-3.2.1.dist-info/RECORD'


def pythonnet_packet(change=None):
    with packet() as original:
        files = {n: original.read(n) for n in original.namelist()}
    stock = json.loads(files['Container_Audit/portable-manifest.json'])
    stock['third_party_versions'] = {'pythonnet': '3.2.1'}
    files['Container_Audit/portable-manifest.json'] = json.dumps(stock).encode()
    rows = []
    for name in NAMES:
        data = name.encode()
        files[RUNTIME + name] = data
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
        rows.append(['pythonnet/runtime/' + name, 'sha256=' + digest, str(len(data))])
    output = io.StringIO()
    csv.writer(output).writerows(rows)
    files[RECORD] = output.getvalue().encode()
    if change:
        change(files)
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr(RUNTIME, b'')
    result.seek(0)
    return zipfile.ZipFile(result)


def test_record_bound_pythonnet_files_are_accepted_repeatedly():
    with pythonnet_packet() as archive:
        service.validate_update_archive(archive, POLICY)
        service.validate_update_archive(archive, POLICY)


@pytest.mark.parametrize('name', NAMES)
def test_each_pythonnet_hash_mismatch_is_rejected(name):
    with pythonnet_packet(lambda files: files.__setitem__(RUNTIME + name, b'changed')) as archive:
        with pytest.raises(ValueError):
            service.validate_update_archive(archive, POLICY)


@pytest.mark.parametrize('path', [RUNTIME + 'fourth.dll', PREFIX + 'other/runtime/Python.Runtime.dll'])
def test_other_nested_runtime_files_remain_denied(path):
    with pythonnet_packet(lambda files: files.__setitem__(path, b'extra')) as archive:
        with pytest.raises(ValueError):
            service.validate_update_archive(archive, POLICY)


@pytest.mark.parametrize('mode', ['missing', 'duplicate', 'oversized', 'unhashed', 'bad_size'])
def test_unusable_pythonnet_record_never_grants_exception(mode):
    def change(files):
        if mode == 'missing':
            del files[RECORD]
        elif mode == 'duplicate':
            files[RECORD] += files[RECORD]
        elif mode == 'oversized':
            files[RECORD] += b' ' * (1024 * 1024)
        elif mode == 'unhashed':
            files[RECORD] = files[RECORD].replace(b'sha256=', b'sha512=')
        else:
            rows = list(csv.reader(io.StringIO(files[RECORD].decode())))
            rows[0][2] = '0'
            output = io.StringIO()
            csv.writer(output).writerows(rows)
            files[RECORD] = output.getvalue().encode()
    with pythonnet_packet(change) as archive:
        with pytest.raises(ValueError):
            service.validate_update_archive(archive, POLICY)


@pytest.mark.parametrize('mutation', ['none', 'hash', 'extra'])
def test_actual_next_release_uses_real_archive_validator(tmp_path, mutation):
    source = os.environ.get('CONTAINER_AUDIT_PYTHONNET_TEST_ZIP')
    if not source:
        pytest.skip('external release ZIP not selected')
    source = Path(source)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == 'c0b73e7a86457a8e75b8a89fb7861885df91adaaf11abc786b024ac428324156'
    if mutation == 'none':
        with zipfile.ZipFile(source) as archive:
            service.validate_update_archive(archive, POLICY)
        return
    copy = tmp_path / 'candidate.zip'
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(copy, 'w', zipfile.ZIP_DEFLATED) as changed:
        for entry in original.infolist():
            data = original.read(entry)
            if mutation == 'hash' and entry.filename == RUNTIME + NAMES[0]:
                data += b'changed'
            changed.writestr(entry, data)
        if mutation == 'extra':
            changed.writestr(RUNTIME + 'fourth.dll', b'extra')
    with zipfile.ZipFile(copy) as archive:
        with pytest.raises(ValueError):
            service.validate_update_archive(archive, POLICY)

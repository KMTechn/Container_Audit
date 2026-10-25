"""Installer-generated task XML, checked by the unchanged product matcher."""
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

import pytest

import auto_update as updates
from tests import _update_host as host


@pytest.fixture
def task_model(tmp_path, monkeypatch):
    current = tmp_path / 'machine' / 'current'
    current.mkdir(parents=True)
    read = host._task_xml_read_model(tmp_path, current, updates)
    monkeypatch.setattr(subprocess, 'run', read)
    return tmp_path, current, read


def test_installer_generated_task_is_accepted(task_model):
    root, current, _ = task_model
    assert updates.supported_task_present(current, host.SID)
    spec = updates.install_task_spec(current, host.SID)
    assert (root / 'task-readback-fixture.xml').read_text(encoding='utf-16') == spec['xml']
    receipt = json.loads((root / 'task-readback-fixture.json').read_bytes())
    assert receipt['generator'] == 'auto_update.install_task_spec -> logon_task_xml'


@pytest.mark.parametrize('path,value', [
    ('Triggers/LogonTrigger/UserId', 'S-1-5-21-100-200-300-9999'),
    ('Actions/Exec/Arguments', '-NoProfile -File invalid.ps1'),
    ('Actions/Exec/Command', 'invalid.exe'),
    ('Principals/Principal/RunLevel', 'LeastPrivilege'),
])
def test_invalid_task_xml_remains_rejected(task_model, monkeypatch, path, value):
    _, current, read = task_model
    namespace = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'

    def altered(command, *args, **kwargs):
        result = read(command, *args, **kwargs)
        task = ET.fromstring(result.stdout)
        task.find('/'.join(namespace + part for part in path.split('/'))).text = value
        return subprocess.CompletedProcess(command, 0, ET.tostring(task, encoding='unicode'), '')

    monkeypatch.setattr(subprocess, 'run', altered)
    assert not updates.supported_task_present(current, host.SID)


def test_other_sid_and_root_queries_are_rejected(task_model):
    _, current, _ = task_model
    assert not updates.supported_task_present(current, 'S-1-5-21-100-200-300-9999')
    assert not updates.supported_task_present(current.parent / 'other', host.SID)


@pytest.mark.parametrize('empty', ['', '<Task/>'])
def test_empty_task_readback_remains_rejected(task_model, monkeypatch, empty):
    _, current, _ = task_model
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, empty, ''))
    assert not updates.supported_task_present(current, host.SID)


def test_unknown_task_read_query_fails_closed(task_model):
    _, _, read = task_model
    query = ['powershell.exe', '-Command', "New-Object -ComObject 'Schedule.Service'; unknown"]
    assert read(query).returncode == 1
    assert read(['unrelated.exe']) is None

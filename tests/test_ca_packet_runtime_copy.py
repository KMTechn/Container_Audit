import json
import os
from pathlib import Path
import subprocess
import sys

from tools import build_portable_release_candidate as builder

ROOT=Path(__file__).resolve().parents[1]
COPY_SMOKE_CODE=r'''import importlib,json,os,sys
from pathlib import Path
root=Path(sys.argv[1]);app=root/'app';sys.path[:0]=[str(app)]
modules=('atomic_replace','runtime_entry','runtime_instance_win32','tk_callback_result','runtime_instance')
for name in modules:
    module=importlib.import_module(name)
    assert Path(module.__file__).resolve().is_relative_to(app.resolve())
import runtime_entry
data=root/'data';data.mkdir()
assert runtime_entry.begin_gui_entry(['--data-root',str(data)],application_path=str(app))
assert runtime_entry._ENTRY is not None
marker=runtime_entry.instance_marker_path(data)
assert json.loads(marker.read_text())['state']=='starting'
runtime_entry.set_gui_state('running')
assert json.loads(marker.read_text())['state']=='running'
runtime_entry.end_gui_entry(force=True)
assert not marker.exists()
from atomic_replace import atomic_replace
prepared=root/'prepared.json';destination=root/'published.json'
prepared.write_text('{"status":"verified"}')
atomic_replace(prepared,destination)
assert json.loads(destination.read_text())=={'status':'verified'}
'''


def test_copy_import_start_and_publication_use_all_new_runtime_modules():
    run=Path(os.environ['IWRUN_CONFIG']).resolve().parent
    packet=run/'packet-smoke'
    app=packet/'app'
    builder._copy_application(ROOT,app)
    for name in ('atomic_replace.py','runtime_entry.py','runtime_instance_win32.py','tk_callback_result.py'):
        assert name in builder.APP_ROOT_FILES
        assert (app/name).read_bytes()==(ROOT/name).read_bytes()
    completed=subprocess.run([sys.executable,'-I','-B','-c',COPY_SMOKE_CODE,str(packet)],
        cwd=ROOT,capture_output=True,text=True,timeout=60)
    assert completed.returncode==0


def test_release_copy_import_closure_names_new_modules(monkeypatch,tmp_path):
    seen=[]
    def capture(command,**kwargs):
        seen.extend(json.loads(command[-1]))
        return subprocess.CompletedProcess(command,0,'','')
    monkeypatch.setattr(builder.subprocess,'run',capture)
    builder._assert_portable_import_closure(ROOT,tmp_path,[],Path(sys.executable))
    assert {'atomic_replace','runtime_entry','runtime_instance_win32','tk_callback_result'}<=set(seen)

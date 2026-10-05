"""Test-only observation immediately before the real install-pack JSON sink.

The companion is a fixture observation, never a product report consumer. CLI
arguments, main implementation, stdout, exit code and actual report stay real.
"""
import copy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import direct_sync_relay_install_pack as install_pack

original_write = install_pack._write_json

def observe_write(path, payload):
    before = copy.deepcopy(payload)
    result = original_write(path, payload)
    path = Path(path)
    path.with_name(path.name + ".before-sink-fixture.json").write_text(
        json.dumps(before, ensure_ascii=True), encoding="utf-8", newline="\n")
    return result

install_pack._write_json = observe_write
if __name__ == "__main__":
    raise SystemExit(install_pack.main(sys.argv[1:]))

"""A joined, headless holder for the real update mutex."""
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.update_mutex_namespace import isolate_update_mutex_names
import auto_update as updates

isolate_update_mutex_names()
control, sid, ready, delay, claim = sys.argv[1:]
control = Path(control)
with updates.update_lock(control, sid):
    if claim == 'live':
        updates.write_json_durable(control / 'apply-claim.json', updates.new_apply_claim())
    Path(ready).write_text('ready', encoding='utf-8')
    time.sleep(float(delay))

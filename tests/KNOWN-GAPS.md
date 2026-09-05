# Known qualification gaps

## Relay stop admission (ca14 source follow-up)

The test audit exposed a product defect: `remove_current_user_setup` holds writer admission while requesting that a live relay stop. The child needs the same admission to persist its final `STOPPED` status, can time out and crash, then releases its runtime mutex. Removal can report `PASS_DATA_PRESERVED` after observing absence despite that crash.

The collected removal test exercises a real relay and proves the current guarantees: persistence removal result, process absence and preserved data. It does not prove a clean relay exit. A separate clean-exit oracle remains red in the audit evidence (`PRODUCT-FINDING-relay-stop-admission.md`, `diagnose_relay_stop.py`); it is outside collection so the agreed single green FULL does not silently become an allowed-red run. No skip or xfail hides this defect. Main accepted this split and assigned a ca14 product source follow-up on 2026-09-06. Move the clean-exit oracle into collection when that fix lands.

## Independent capture validator

The authoritative external capture validator is unavailable. Its dedicated contract comparison explicitly skips; real builder PNG/state/hash checks run independently. See [contracts/README.md](contracts/README.md).

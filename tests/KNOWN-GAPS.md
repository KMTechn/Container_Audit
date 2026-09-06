# Known qualification gaps

## Relay stop admission (ca14 source follow-up)

The test audit exposed a product defect: `remove_current_user_setup` holds writer admission while requesting that a live relay stop. The child needs the same admission to persist its final `STOPPED` status, can time out and crash, then releases its runtime mutex. Removal can report `PASS_DATA_PRESERVED` after observing absence despite that crash.

The collected removal test exercises a real relay and proves the current guarantees: persistence removal result, process absence and preserved data. It does not prove a clean relay exit. A separate clean-exit oracle remains red in the audit evidence (`PRODUCT-FINDING-relay-stop-admission.md`, `diagnose_relay_stop.py`); it is outside collection so the agreed single green FULL does not silently become an allowed-red run. No skip or xfail hides this defect. Main accepted this split and assigned a ca14 product source follow-up on 2026-09-06. Move the clean-exit oracle into collection when that fix lands.

## Independent capture validator

The authoritative external capture validator is unavailable. Its dedicated contract comparison explicitly skips; real builder PNG/state/hash checks run independently. See [contracts/README.md](contracts/README.md).

## Duplicate-notice recent-row context (ca14 usability candidate)

Native Tk measurement at 1366x768, clam theme and Tcl scaling 2.00098 shows that a blocking duplicate notice can shrink the scan list. At application scale 1.4 its y/height changes from 541/154 to 599/96, while action buttons remain fixed and contained. With ten rows and the list initially scrolled to the end, complete visible rows at scales 1.0/1.1/1.2/1.3/1.4 are 6/5/4/3/2; the newest row is partially clipped at every measured scale except 1.2. The collected test requires at least one complete recent row, preserved data/last-normal state, fixed contained actions and geometry restored after acknowledgement. Main classified the context loss as a usability candidate, not a required product defect, on 2026-09-06; unchanged geometry during the warning was a fake-widget-only claim.

## Compact right-sidebar values clipped (ca14 product usability finding)

Building the native widgets directly at application scale 1.4, 1366x768 viewport, clam theme and Tcl scaling 2.00098 places secondary values outside a 302x707 right pane. The average value occupies relative x/y/width/height 12/691/130/36 (20px below the pane); the best value occupies 160/710/130/36 (entirely below the pane, with its bottom 39px beyond it). A separate diagnostic produced the same geometry when built directly at 1.4 and when rescaled from 1.0. The primary status and follow-up values remain contained.

The collected `test_operator_widget_transitions.py::test_native_right_cards_and_legend_restore_after_compact_round_trip` builds directly at the target scale and asserts the actual containment requirement. It remains red with no skip or xfail, as Main explicitly directed on 2026-09-06 at 08:32 KST. The prior fake-widget test only inspected fonts, padding and layout flags and did not measure whether operators could read the secondary values. This finding requires a separate product change; a green full-suite result cannot be claimed until it is resolved.

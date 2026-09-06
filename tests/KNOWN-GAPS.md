# Known qualification gaps

## Resolved CA14 source regressions

`test_current_user_onboarding.py::test_public_remove_clears_user_persistence_but_preserves_data` now calls the real public remover with its default stopper and asserts natural owned-child exit 0, persisted `STOPPED`, runtime lease absence, empty child stderr and exact protected/business byte preservation after the call. The real production relay first completes a successful cycle in its supported operator-paused state, keeping this shutdown regression independent of credential provisioning or uploads. The identical collected oracle fails on baseline `8a746ac` specifically at the admission-dependent terminal write after public PASS/ABSENT, and passes with admission scoped to mutations. Existing real-child upload and active-fence negative controls remain separate and run; the pause fixture does not prove unpaused native shutdown.

The unchanged `test_operator_widget_transitions.py::test_native_right_cards_and_legend_restore_after_compact_round_trip` now passes at application scale 1.4, Tcl scaling 2.00098, 1366x768 viewport and 302x707 pane. Required values remain mapped/contained through compact-large-compact, with the larger legend restored. Its supported-scale companion verifies full rendered blocked/ready/pending/review status text, allocated text height, card containment and unchanged value fonts at scales 1.0-1.4; this also covers the multiline primary status clipping discovered during the visible CA14 smoke. Compact captions and content-sized rows replace overflowing decorative minima.

Preserved source evidence is indexed by `E:/KMTech/coordinator-takeover-20260905/ca14-source/CA14-SOURCE-REVIEW.md`: original containment and admission failures, the identical paused-fixture red/green pair, and the rendered-content red (`46px` allocated versus `100px` required) and green matrix. Historical failures remain failed. These source regressions do not replace fresh exact-packet installed/native qualification.

## Independent capture validator

The authoritative external capture validator is unavailable. Its dedicated contract comparison explicitly skips; real builder PNG/state/hash checks run independently. See [contracts/README.md](contracts/README.md).

## Duplicate-notice recent-row context (ca14 usability candidate)

Native Tk measurement at 1366x768, clam theme and Tcl scaling 2.00098 shows that a blocking duplicate notice can shrink the scan list. At application scale 1.4 its y/height changes from 541/154 to 599/96, while action buttons remain fixed and contained. With ten rows and the list initially scrolled to the end, complete visible rows at scales 1.0/1.1/1.2/1.3/1.4 are 6/5/4/3/2; the newest row is partially clipped at every measured scale except 1.2. The collected test requires at least one complete recent row, preserved data/last-normal state, fixed contained actions and geometry restored after acknowledgement. Main classified the context loss as a usability candidate, not a required product defect, on 2026-09-06; unchanged geometry during the warning was a fake-widget-only claim.

# Running the repository tests

Use the supported Windows Python environment with the dependencies declared by this repository installed. Test commands never install dependencies. From the repository root:

```powershell
python -B tools/run_repository_tests.py --work-root E:\KMTech\ca-tests
python -B tools/run_repository_tests.py --work-root E:\KMTech\ca-tests tests/test_writer_session_fence.py
```

The runner disables ambient pytest plugins, allocates a unique owned directory under `.test-runs`, and records stdout, stderr, JUnit and the exact command. `--work-root <owned-directory>` selects a shorter path for Windows integration runs. Each test receives a short temporary path and separate product state, with child writer isolation propagated through `tests/sitecustomize.py`. The canonical production writer mutex is denied before native acquisition. The fixture restores process environment patches after each test.

Use the explicit E work root above to satisfy the workspace storage policy, and keep its path short: Windows PowerShell 5.1 file APIs can reject a long receipt path even when Python accepts it. A source archive alone does not supply Git provenance. Prepare the source with its authentic commit, tree, object history, refs and index; do not replace that context with an empty `git init` or an invented commit. Product blob checks remain enabled for development snapshots with explicitly recorded fixture changes.

The affected PowerShell contract helpers use `tests/powershell_contracts.py` to set console output to UTF-8 and decode both streams strictly on the calling thread, preserving text newline handling. File invocations run the original script in its own scope through a quoted `-Command` call so encoding is established before diagnostics are emitted. `tests/native_process_fixtures.py` launches the actual Windows base interpreter with CPython's venv launcher environment, preserving venv packages while giving the owner the real interpreter PID. Canonical relay fixtures own cleanup before startup and preimage assertions, and the exact-artifact fixture copies and hashes the base executable. `tests/test_process_fixture_boundaries.py` covers these boundaries; these checks do not establish target codepage, installer qualification or FULL acceptance.

Direct `python -B -m pytest` is also supported by the committed conftest; callers should set `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` to avoid unrelated installed plugins. Pass an owned `--basetemp` to control all test output. Native process tests require Windows PowerShell and local child-process capability; unavailable 8.3 paths and ACL privileges remain explicit capabilities.

Tests marked `native_e_drive` exercise tools whose production output policy requires an E drive. They run when the temporary directory meets that policy, or with `--native-e-root <owned-directory-below-E-drive-KMTech>`, and otherwise report a capability skip. Pure path-policy tests run without the drive. The runner can receive that pytest option after `--work-root`.

Pinned server contracts and their exact coverage boundary are documented in [contracts/README.md](contracts/README.md). Missing authoritative contract artifacts are reported as skips, never as passed qualification. Ordinary tests use the GUI fail-fast guard; the separately marked widget lane is documented with its prerequisites when enabled.

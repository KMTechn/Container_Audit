# Running the repository tests

Use the supported Windows Python environment with the dependencies declared by this repository installed. Test commands never install dependencies. From the repository root:

```powershell
python -B tools/run_repository_tests.py
python -B tools/run_repository_tests.py tests/test_writer_session_fence.py
```

The runner disables ambient pytest plugins, allocates a unique owned directory under `.test-runs`, and records stdout, stderr, JUnit and the exact command. `--work-root <owned-directory>` selects a shorter path for Windows integration runs. Each test receives a short temporary path and separate product state, with child writer isolation propagated through `tests/sitecustomize.py`. The canonical production writer mutex is denied before native acquisition. The fixture restores process environment patches after each test.

Direct `python -B -m pytest` is also supported by the committed conftest; callers should set `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` to avoid unrelated installed plugins. Pass an owned `--basetemp` to control all test output. Native process tests require Windows PowerShell and local child-process capability; unavailable 8.3 paths and ACL privileges remain explicit capabilities.

Tests marked `native_e_drive` exercise tools whose production output policy requires an E drive. They run when the temporary directory meets that policy, or with `--native-e-root <owned-directory-below-E-drive-KMTech>`, and otherwise report a capability skip. Pure path-policy tests run without the drive. The runner can receive that pytest option after `--work-root`.

Pinned server contracts and their exact coverage boundary are documented in [contracts/README.md](contracts/README.md). Missing authoritative contract artifacts are reported as skips, never as passed qualification. Ordinary tests use the GUI fail-fast guard; the separately marked widget lane is documented with its prerequisites when enabled.

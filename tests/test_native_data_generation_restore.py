"""Native code restore after actual isolated onboarding must retain new code."""
import json
from pathlib import Path
import shutil

from auto_update import source_version_literal

from tests.test_canonical_installation_callers import _distinct_replacement, _public_restore
from tests.test_canonical_portable_uninstall import (
    _assert_one_live_relay, _assert_preserved_and_released, _install,
    _launch_relay, _live_preimage, _setup, _tree,
)


def test_public_restore_after_data_open_retains_new_code_and_runtime(tmp_path):
    env, source, install, protected = _setup(tmp_path)
    # 416 source admission uses the stock's manifest/version bytes rather than
    # an installation integrity record. Bind this otherwise partial fixture
    # to the real version file without bypassing either admission guard.
    version_file = Path(__file__).resolve().parents[1] / 'Container_Audit.py'
    shutil.copyfile(version_file, source / 'app/Container_Audit.py')
    manifest_path = source / 'portable-manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    manifest['version'] = source_version_literal(version_file.read_bytes())
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    canonical = source / 'INSTALL_CANONICAL_PORTABLE.ps1'
    text = canonical.read_text(encoding='utf-8-sig')
    observer_point = '    $outputFailure=$_'
    assert text.count(observer_point) == 1
    # Observe the actual original error before the real public sink. Only
    # typed location and a cause predicate leave that boundary; no raw text.
    text = text.replace(observer_point, observer_point + r'''
    if ($env:CA_DATA_OPEN_OBSERVE -ceq '1') {
        $observation=@{original_unknown=([string]$outputFailure.Exception.Message).Contains('자료 판을 확인할 수 없어');
            type=$outputFailure.Exception.GetType().FullName;
            script=$outputFailure.InvocationInfo.ScriptName;line=$outputFailure.InvocationInfo.ScriptLineNumber}
        [IO.File]::WriteAllText((Join-Path $env:CA_UNINSTALL_ROOT 'restore-original-guard.json'),($observation|ConvertTo-Json -Compress))
    }
''')
    canonical.write_text(text, encoding='utf-8-sig')
    _distinct_replacement(source)
    with _launch_relay(tmp_path, env) as child:
        before = _live_preimage(tmp_path, env, source, install, child)
        replaced = _install(tmp_path, env, source, install)
        assert replaced.returncode == 0, replaced.stderr
        replacement = json.loads((tmp_path / "reinstall-audit.json").read_text(encoding="utf-8-sig"))["code_replacement"]
        receipt = Path(replacement["receipt_path"])
        receipt_before = receipt.read_bytes()
        new_code = _tree(install)
        registry_before = json.loads((tmp_path / "registry.json").read_text(encoding="utf-8-sig"))
        _, runtime_before = _assert_one_live_relay(tmp_path, env)
        local = Path(env["LOCALAPPDATA"])
        markers = [local / "KMTech/ContainerAudit/data-generation.json",
                   *list((local / "KMTech/DirectSync/container_audit/control/writer-session/data-generation").glob("*.json"))]
        assert len(markers) == 2 and all(path.is_file() for path in markers)
        marker_before = {path: path.read_bytes() for path in markers}

        env['CA_DATA_OPEN_OBSERVE'] = '1'
        refused = _public_restore(tmp_path, env, source, install, receipt, replacement["receipt_sha256"])

        failures = [json.loads(line.split('=', 1)[1]) for line in refused.stdout.splitlines()
                    if line.startswith('CONTAINER_AUDIT_INSTALL_CANONICAL=')]
        assert len(failures) == 1
        failure = failures[0]
        assert failure['status'] == 'FAILED'
        assert failure['stage'] == 'canonical_install'
        assert failure['reason_code'] == 'INSTALLER_CANONICAL_FAILURE'
        assert refused.returncode == failure['exit_code'] == 1 and refused.stderr == ''
        assert failure['report_status'] == 'REPORT_UNAVAILABLE'
        assert not any(key in failure for key in ('message', 'detail', 'traceback', 'stderr', 'report_path', 'report_sha256'))
        original = json.loads((tmp_path / 'restore-original-guard.json').read_bytes())
        assert original['original_unknown'] is True
        assert original['type'] == failure['exception_type'] == 'System.Management.Automation.RuntimeException'
        guard = source / 'tools/bootstrap_integrity.ps1'
        assert Path(original['script']).resolve() == guard.resolve()
        guard_lines = guard.read_text(encoding='utf-8-sig').splitlines()
        throws = [number for number, line in enumerate(guard_lines, 1)
                  if line.strip() == 'if (-not $decision.allowed) { throw $decision.message }']
        assert throws == [failure['location_line']] == [original['line']]
        assert _tree(install) == new_code and _tree(source) == before["source"]
        assert receipt.read_bytes() == receipt_before
        assert {path: path.read_bytes() for path in markers} == marker_before
        # Native registry values are exact; the OS fixture may reserialize JSON.
        assert json.loads((tmp_path / "registry.json").read_text(encoding="utf-8-sig")) == registry_before
        _assert_preserved_and_released(env, protected)
        launches, runtime = _assert_one_live_relay(tmp_path, env)
        assert runtime["CommandLine"] == runtime_before["CommandLine"]
        assert launches[-1]["fence_active"] is False

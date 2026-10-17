"""G62: a sibling entrypoint's definitions cannot satisfy a fresh PS scope."""
import json
from pathlib import Path
import shutil

import pytest

from tests.powershell_contracts import run_powershell

ROOT = Path(__file__).resolve().parents[1]
SHARED = ('tools/bootstrap_integrity.ps1', 'kmtech_shared/powershell/portable.ps1',
          'kmtech_shared/powershell/data_generation.ps1', 'tools/container_writer_fence.ps1')
# Static/dot-source closure of the independently launched runtime entries. The
# load-order audit separately checks that shared definitions dominate calls.
ENTRIES = {
    'INSTALL_THIS_PC.ps1': SHARED,
    'INSTALL_CANONICAL_PORTABLE.ps1': SHARED,
    'tools/apply_prepared_update.ps1': SHARED,
    'tools/container_writer_session.ps1': SHARED,
    'tools/provision_protected_admin_acl.ps1': SHARED,
    'tools/build_frozen_release_candidate.ps1': (*SHARED,
        'tools/resolve_release_python.ps1', 'tools/resolve_windows_powershell.ps1'),
    'tools/prepublish_release_gate.ps1': (),
    'tools/scan_portable_pe.ps1': (),
    'tools/sandbox_container_sac/guest.ps1': (),
    'tools/sandbox_container_sac/run.ps1': (),
}
MODULES = ('Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility',
           'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Core',
           'Microsoft.PowerShell.Archive', 'Microsoft.PowerShell.Diagnostics',
           'CimCmdlets', 'ScheduledTasks', 'Microsoft.PowerShell.LocalAccounts')
ALLOWED = {
    # BI:2090-2095 loads canonical definitions before coordinator/compensation.
    'Get-CanonicalInstallationCommitPoint': 'Coordinator loads canonical before commit-point readback.',
    'Restore-CanonicalApplicationProtection': 'Coordinator loads canonical before compensation restores ACLs.',
    'Sync-CanonicalWriterFenceInventory': 'Coordinator loads canonical before compensation inventory sync.',
    'Assert-CanonicalTransactionRelayPreimage': 'Coordinator loads canonical before relay preimage checks.',
    'Assert-CanonicalTransactionInstalledCandidate': 'Coordinator loads canonical before candidate checks.',
    'Read-CanonicalHelperArtifact': 'Coordinator loads canonical before helper artifact readback.',
    'Assert-CanonicalRollbackStopCleanup': 'Coordinator loads canonical before rollback cleanup checks.',
    'Restore-CanonicalOfficialLegacyRelay': 'Coordinator loads canonical before legacy relay restoration.',
    'Enable-CanonicalWriter': 'Coordinator loads canonical before writer restoration.',
    'Assert-CanonicalWriterRestoreReadback': 'Coordinator loads canonical before restored writer checks.',
    'New-CanonicalWriterFenceReleaseAuthorization': 'Coordinator loads canonical before release authorization.',
    'Set-CanonicalWriterFenceReleaseAuthorization': 'Coordinator loads canonical before release authorization publication.',
    'Clear-CanonicalWriterFenceReleaseDelegation': 'Coordinator loads canonical before delegation cleanup.',
    'Stop-CanonicalWriterFenceRelease': 'Coordinator loads canonical before fence release.',
    'Start-CanonicalRelayAfterFenceRelease': 'Coordinator loads canonical before relay restart.',
    'Confirm-CanonicalWriterRunning': 'Coordinator loads canonical before writer readback.',
    'Get-CanonicalRollbackSuccessStatus': 'Coordinator loads canonical before rollback status calculation.',
    'Assert-CanonicalTransactionCommit': 'Coordinator loads canonical before commit readback.',
    'Initialize-CanonicalUserProcessApi': 'BI:2375-2382 extracts and evaluates this exact pinned canonical definition.',
    'Assert-ProtectedCodeAncestors': 'Protect-KmtechCodeAncestors is an ITP callback; ITP defines its trust validator.',
}


def callback_exceptions():
    rows = []
    for name, reason in ALLOWED.items():
        if name == 'Assert-ProtectedCodeAncestors':
            owners, provider = ['Protect-KmtechCodeAncestors'], 'INSTALL_THIS_PC.ps1'
        elif name == 'Initialize-CanonicalUserProcessApi':
            owners, provider = ['Import-BootstrapCanonicalUserProcessApi'], 'INSTALL_CANONICAL_PORTABLE.ps1'
        else:
            owners = ['Invoke-CanonicalTransactionCompensation', 'Invoke-InstallationTransactionCoordinator']
            provider = 'INSTALL_CANONICAL_PORTABLE.ps1'
        rows.append(dict(name=name, reason=reason, owners=owners, provider=provider))
    return rows


@pytest.mark.parametrize('entry', ENTRIES)
def test_entry_verb_noun_commands_resolve_in_own_load_set(tmp_path, entry):
    engine = shutil.which('powershell.exe')
    assert engine, 'Windows PowerShell 5.1 required'
    config = tmp_path / 'scope.json'
    config.write_text(json.dumps({'files': [entry, *ENTRIES[entry]],
        'modules': MODULES, 'allowed': callback_exceptions()}), encoding='utf-8')
    audit = tmp_path / 'audit.json'
    result = run_powershell([engine, '-NoLogo', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / 'tests/ps_entry_command_audit.ps1'),
        '-Root', str(ROOT), '-Entry', entry, '-ConfigurationPath', str(config), '-AuditPath', str(audit)])
    assert audit.exists(), 'command-scope audit did not complete'
    report = json.loads(audit.read_text(encoding='utf-8-sig'))
    assert result.returncode == 0, [(r['path'], r['line'], r['name']) for r in report['missing']]
    assert report['commands'] > 0

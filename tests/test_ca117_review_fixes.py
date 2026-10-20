"""Transfer 117 review fixes: guidance the entry really accepts, and a durable move journal."""
import json
import re
from pathlib import Path

from tests.powershell_contracts import run_functions

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "INSTALL_CANONICAL_PORTABLE.ps1"
HELPER = REPO / "INSTALL_THIS_PC.ps1"

GUIDANCE_DRIVER = r'''
$ErrorActionPreference='Stop'
function Resolve-CanonicalWorkerSid([string]$Account) { return $env:CA_TEST_SID }
function Get-CanonicalWorkerProfileRoot([string]$Sid) { return $env:CA_TEST_PROFILE }
function Assert-BootstrapNoReparsePoint { param($Path,$Label,[switch]$PathOnly) }
function Get-CanonicalConsoleWorkerSecurity { throw 'console path must not be used' }
$audit=@{operation='UNINSTALL'}
$guidance=Get-CanonicalMachineRecoveryEntry $audit 'C:\audit\canonical-portable-x.json'
$account=''
$inventory=''
if ($guidance -match '-WorkerAccount ') { $account=$env:CA_TEST_SID }
if ($guidance -match '-WorkerSurveyInventory ') { $inventory=$env:CA_TEST_INVENTORY }
$caller=[pscustomobject]@{sid='S-1-5-18';elevated=$true;session_id=0}
$observed=''
try { [void](Resolve-CanonicalMachineWorker $account $inventory $caller) } catch { $observed=$_.Exception.Message }
[IO.File]::WriteAllText((Join-Path $env:CA_CONTRACT_ROOT 'guidance.json'),(@{guidance=$guidance;observed=$observed}|ConvertTo-Json))
'GUIDANCE DONE'
'''


def test_failed_uninstall_guidance_arguments_pass_the_entry_worker_check(tmp_path):
    sid = "S-1-5-21-1-2-3-1001"
    profile = tmp_path / "profile"
    profile.mkdir()
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"status": "READY", "target_sid": sid, "target_profile_root": str(profile)}),
                         encoding="utf-8")
    result = run_functions(tmp_path, INSTALLER,
                           ["Full", "Same", "Get-CanonicalMachineRecoveryEntry", "Resolve-CanonicalMachineWorker"],
                           GUIDANCE_DRIVER, values={"CA_TEST_SID": sid, "CA_TEST_PROFILE": str(profile),
                                                    "CA_TEST_INVENTORY": str(inventory)})
    assert result.returncode == 0 and "GUIDANCE DONE" in result.stdout, result.stdout + result.stderr
    outcome = json.loads((tmp_path / "guidance.json").read_text(encoding="utf-8-sig"))
    assert "-WorkerSurveyInventory" in outcome["guidance"], outcome["guidance"]
    assert outcome["observed"] != "PENDING_TARGET_AMBIGUOUS", outcome


def test_support_documentation_names_the_inventory_argument():
    text = (REPO / "docs/spec/admin-installation.md").read_text(encoding="utf-8")
    start = text.index("이 입구의 정확한 인수 꼴")
    assert "-WorkerSurveyInventory" in text[start:start + 300]


def test_move_journal_writer_flushes_to_disk_before_the_rename():
    text = HELPER.read_text(encoding="utf-8-sig")
    line = next(row for row in text.splitlines() if "$journalWrite = {" in row)
    assert "AppendAllText" not in line, line
    assert "Flush($true)" in line, line
    assert "FileMode]::Append" in line or "FileMode]::OpenOrCreate" in line or "[IO.FileMode]" in line
    # the MOVE record is written before the rename in the same loop
    assert text.index("record='MOVE'") < text.index("Move-Item -LiteralPath (Get-ContainerRemovalIoPath $path) -Destination $destinationIo")


def test_move_journal_writer_flushes_through_a_real_stream(tmp_path):
    text = HELPER.read_text(encoding="utf-8-sig")
    line = next(row for row in text.splitlines() if "$journalWrite = {" in row).strip()
    driver = ("$ErrorActionPreference='Stop'\n$moveJournal=$env:CA_JOURNAL\n"
              "$journalEncoding=[Text.UTF8Encoding]::new($false)\n" + line + "\n"
              "& $journalWrite ([ordered]@{record='MOVE';path='a'})\n& $journalWrite ([ordered]@{record='MOVE';path='b'})\n'OK'\n")
    journal = tmp_path / "j.jsonl"
    result = run_functions(tmp_path, HELPER, ["Get-ContainerRemovalIoPath"], driver, values={"CA_JOURNAL": str(journal)})
    assert result.returncode == 0 and "OK" in result.stdout, result.stdout + result.stderr
    rows = [json.loads(r) for r in journal.read_text(encoding="utf-8").splitlines()]
    assert [r["path"] for r in rows] == ["a", "b"]
    assert not re.match(r"^\ufeff", journal.read_text(encoding="utf-8"))

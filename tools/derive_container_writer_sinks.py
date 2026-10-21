from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_RELATIVE_PATH = Path("tools/container_writer_sink_inventory.json")
BYTE_EXACT_CHECKOUT_PATHS = (SNAPSHOT_RELATIVE_PATH, Path("tools/bootstrap_integrity.ps1"))
SNAPSHOT_PATH = ROOT / SNAPSHOT_RELATIVE_PATH

SHIPPED_PACKAGE_DIRS = ("kmtech_factory_contracts", "kmtech_shared", "vendor")
# The new-screen bridge's pinned companion kit is analysed even before portable assembly.
SCREEN_SHELL_DIR = "shell"
SHELL_KIT_READY_VERSION = "v3.16.3.1"
SHELL_KIT_READY_SHA256 = "19389ecbdc0af9288f93015929975e5c603ff3c2066290d166742efea952ab71"
SHELL_KIT_PYTHON_SHA256 = {'shell/bridge.py': '1a7e53db0d18f022d86d936d8666d5d13028873e8a10945cbd78f96995b1456b', 'shell/event_order.py': '48075f599c33bef1b9a3a283717d31f50f00ac2e71b1ebeb6970620b2275c146', 'shell/host.py': 'd3aaf6549fff429384ac262eaf32de5cf440daba1e220936e37579b231df5d02', 'shell/journal.py': '5d486cde397f93d1b8d651fec273e667399c5860d1481cc86232341bb1a0aa4d', 'shell/pedal.py': 'fe19337649eddcc804398f410e022fce91bead708159ae3f82ae01dc790312f9', 'shell/scan_rules.py': 'a07e19eaac003b775adbe93fac86ce1536cf1e83729f7c654279e5f0c09f1504', 'shell/shell_fileio.py': 'b1d993c466d1df5161330c25389c35bd295b7f02a6c566b544bdac3072968101', 'shell/sound.py': 'a007064433046d9b1debfb183d1db28fb88f585230dcaa2937d175993f308504'}
SHELL_KIT_WRITE_MODULE = "shell.shell_fileio"
SHELL_KIT_WRITE_SITES = ("append_bytes", "create_new", "truncate", "replace_atomic", "make_dirs", "probe_writable", "remove")
SHELL_KIT_WRITER_SOURCE = "screen_shell_fileio"
SHARED_UNUSED_DIAGNOSTIC_SHA256 = "085c47ad7cf42130de74240a6e3dccefc2502d844591f775d46fedaabc6ad36b"
PS_MODULE_PROLOGUE = (
    b"Import-Module -Name (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop\n"
    b"Import-Module -Name (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop\n"
)
SHIPPED_PORTABLE_ENTRYPOINTS = (Path("portable/main.py"),)
POWERSHELL_PATHS = (
    Path("kmtech_shared/powershell/portable.ps1"),
    Path("kmtech_shared/powershell/data_generation.ps1"),
    Path("tools/bootstrap_integrity.ps1"),
    Path("tools/container_writer_session.ps1"),
    Path("INSTALL_CANONICAL_PORTABLE.ps1"),
    Path("INSTALL_THIS_PC.ps1"),
    Path("tools/container_writer_fence.ps1"),
    Path("tools/apply_prepared_update.ps1"),
)
POWERSHELL_LIBRARY_PATHS = frozenset(
    {
        Path("kmtech_shared/powershell/portable.ps1"),
        Path("kmtech_shared/powershell/data_generation.ps1"),
        Path("tools/bootstrap_integrity.ps1"),
        Path("tools/container_writer_fence.ps1"),
    }
)
COMMON_FENCE_GUARD_PREFIX = "Invoke-ContainerWriterFenceMutation"
POWERSHELL_PLACEMENT_SOURCE = "canonical_code_placement"
POWERSHELL_ENTRYPOINT_GUARDS: dict[Path, dict[str, Any]] = {
    Path("tools/apply_prepared_update.ps1"): {
        "entry_guard": "Enter-ContainerStartupUpdateAuthority",
        "release_guard": "",
        "guard_kind": "startup_update_system_authority",
        "writer_source": "auto_update_control",
    },
    Path("INSTALL_CANONICAL_PORTABLE.ps1"): {
        "entry_guard": "Enter-ContainerWriterSessionAuthority",
        "release_guard": "Exit-ContainerWriterSessionAuthority",
        "guard_kind": "session_authority",
        "writer_source": "",
    },
    Path("INSTALL_THIS_PC.ps1"): {
        "entry_guard": "Enter-ContainerPlacementWriterFence",
        "release_guard": "Exit-ContainerWriterAdmission",
        "guard_kind": "delegated_operation",
        "internal_guard_function": "Enter-ContainerPlacementWriterFence",
        "internal_guard": "Enter-ContainerWriterDelegatedOperation",
        "prelaunch_boundary": "Invoke-SelfElevated",
        "writer_source": POWERSHELL_PLACEMENT_SOURCE,
    },
    Path("tools/container_writer_session.ps1"): {
        "entry_guard": "Assert-ContainerWriterPublicInvocation",
        "release_guard": "",
        "guard_kind": "session_contract",
        "writer_source": "",
    },
}
POWERSHELL_NON_PRODUCTION_FUNCTION_MODES: dict[Path, dict[str, str]] = {
    Path("tools/container_writer_session.ps1"): {
        "Invoke-ContainerWriterSessionSelfTest": "selftest",
    },
}
POWERSHELL_APPROVED_DOT_SOURCE_SYMBOLS: dict[Path, frozenset[str]] = {
    Path("tools/bootstrap_integrity.ps1"): frozenset({"$dataGenerationLeaf"}),
    Path("tools/apply_prepared_update.ps1"): frozenset({"$IntegrityHelper", "$SharedLeaf"}),
    Path("INSTALL_CANONICAL_PORTABLE.ps1"): frozenset(
        {"$writerFenceHelperPath", "$BootstrapIntegrityFunctions", "$sharedLeaf"}
    ),
    Path("INSTALL_THIS_PC.ps1"): frozenset(
        {"$BootstrapIntegrityFunctions", "$writerFenceHelperFull", "$writerFenceHelperPath"}
    ),
    Path("tools/container_writer_session.ps1"): frozenset(
        {"$Script:IntegrityHelperPath", "$Script:WriterFenceHelperPath"}
    ),
    Path("tools/container_writer_fence.ps1"): frozenset({"$ContainerAtomicLibrary"}),
}
POWERSHELL_FILESYSTEM_MUTATION_COMMANDS = (
    "Invoke-ContainerAtomicReplace",
    "Add-Content",
    "Clear-Content",
    "Copy-Item",
    "Move-Item",
    "New-Item",
    "Out-File",
    "Remove-Item",
    "Rename-Item",
    "Set-Acl",
    "Set-Content",
)
POWERSHELL_REGISTRY_MUTATION_COMMANDS = (
    "New-ItemProperty",
    "Remove-ItemProperty",
    "Rename-ItemProperty",
    "Set-ItemProperty",
)
POWERSHELL_REFLECTION_COMMANDS = (
    "InvokeMember",
    "GetMethod",
    "GetMethods",
    "MethodInfo",
    "Activator]::CreateInstance",
)
POWERSHELL_DIRECT_COMMAND_NAMES = (
    "at",
    "cmd",
    "cscript",
    "icacls",
    "mshta",
    "msiexec",
    "net",
    "netsh",
    "powershell",
    "pwsh",
    "reg",
    "regsvr32",
    "rundll32",
    "schtasks",
    "wmic",
    "wscript",
)
POWERSHELL_NATIVE_PROCESS_APIS = (
    "CreateProcess",
    "CreateProcessAsUser",
    "CreateProcessWithLogonW",
    "CreateProcessWithTokenW",
    "NtCreateUserProcess",
    "RtlCreateUserProcess",
    "ShellExecute",
    "ShellExecuteEx",
    "WinExec",
)

# Fold only the 33 pre-existing b82 directory preparations into their unchanged callers.
ATOMIC_REPLACEMENT_HELPER = "atomic_replace.atomic_replace"
ATOMIC_REPLACEMENT_MODULE_AST_SHA256 = "d4b3034a10a68e0ce8f744361be629967666a16b9850e004e210d909e89958c0"
POWERSHELL_ATOMIC_HELPERS_SHA256 = "9ca4943f643b639cfa68a5787e12be99409e06474d444ceae6d81e468fd7139c"
POWERSHELL_ATOMIC_FUNCTIONS = frozenset({"Invoke-ContainerAtomicReplace", "Invoke-ContainerAtomicReplaceOnce"})
DIRECTORY_PREPARATION_HELPER = "storage_policy.ensure_user_runtime_directory"
DIRECTORY_PREPARATION_HELPER_AST_SHA256 = '0dbccb4e84da1737ae39f266bab8727b5d7836768211e32b38d7432bf206b7a0'
DIRECTORY_PREPARATION_CALLS = {
    ('Container_Audit.ContainerAudit._prepare_tray_state_snapshot', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('gui_tray_state_save', (), True, False),
    ('auto_update.create_download_stage', 'ff08243590989fdc2c4104ebb0a9e30ebb2840a7352f86651027a50e88181892'): ('auto_update_control', (), False, False),
    ('container_audit_product_host._append_jsonl', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('hosted_relay_jsonl', (), False, False),
    ('container_audit_product_host._write_json_atomic', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('hosted_relay_json', (), False, False),
    ('current_user_onboarding._write_json_atomic', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('current_user_onboarding_storage', (), False, False),
    ('current_user_onboarding._write_json_atomic_create_new', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('current_user_onboarding_storage', (), False, False),
    ('current_user_onboarding.onboard_current_user', '87f9ed34d31694cef448ad430f4bf2d47211409a8649376df30813e5b8d1bd2f'): ('current_user_onboarding', ('current_user_onboarding',), True, False),
    ('current_user_onboarding.remove_current_user_setup', 'baed5eba0765259aa71ca7259034e47e8c4d38ae2520bd286c7010aebaacf367'): ('current_user_setup_removal', ('current_user_setup_removal',), False, False),
    ('data_generation_guard.record_before_data_open', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('data_generation_marker', (), False, False),
    ('direct_sync_auto_bootstrap._write_json', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('bootstrap_status', (), False, False),
    ('direct_sync_operator._append_jsonl', 'b762147a0575a9c219141d905cb359521ef4b0ae6053a719380332f546acf71a'): ('operator_evidence', (), False, False),
    ('direct_sync_operator._write_json_atomic', 'b762147a0575a9c219141d905cb359521ef4b0ae6053a719380332f546acf71a'): ('operator_evidence', (), False, False),
    ('direct_sync_push._connect_relay_db', 'd5df6ba5f1a7dc72c635a9e2c7d7432df671867262848001585ebe173c53aa1c'): ('relay_spool_storage', (), False, False),
    ('direct_sync_push._copy_file_atomic', 'a70fad8c3d201be97fbd6f298609417170004bcba06831df4282efd9f24818b9'): ('relay_spool_storage', (), False, False),
    ('direct_sync_push._prepare_status_temp', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('relay_upload_status', (), True, False),
    ('direct_sync_push._write_json_atomic', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('relay_spool_storage', (), False, False),
    ('direct_sync_push.restore_raw_artifact_to_file', 'a70fad8c3d201be97fbd6f298609417170004bcba06831df4282efd9f24818b9'): ('relay_spool_storage', ('relay_spool_storage',), True, False),
    ('direct_sync_runtime._append_jsonl', 'b762147a0575a9c219141d905cb359521ef4b0ae6053a719380332f546acf71a'): ('relay_runtime_storage', (), False, False),
    ('direct_sync_runtime._disk_pressure_report', '4e7f6fa8c515ed6b491f1a84f8f664a79648d680b6eefe8318d738cac1d00dd1'): ('relay_runtime_storage', (), False, False),
    ('direct_sync_runtime._write_json_atomic', 'b762147a0575a9c219141d905cb359521ef4b0ae6053a719380332f546acf71a'): ('relay_runtime_storage', (), False, False),
    ('portable.main._portable_smoke', '2124167f079b9b08eae07cba3fe97b52c2aec8f42806ef3394c2e69ab4eeca18'): ('portable_smoke_marker', (), False, False),
    ('runtime_instance._write_entry_marker', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('runtime_instance_marker', (), False, True),
    ('storage_policy.ensure_container_audit_storage_dirs', '87f9ed34d31694cef448ad430f4bf2d47211409a8649376df30813e5b8d1bd2f'): ('', (), False, False),
    ('tools.direct_sync_relay_install_pack._apply_task_runtime_acl', 'ac4ab861b2316abcfe9281f7dce3de82d63d5ff49ee532f00ed01e5ffa940529'): ('direct_sync_install_pack', (), False, False),
    ('tools.direct_sync_relay_install_pack._write_json', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('direct_sync_install_pack', (), False, False),
    ('tools.direct_sync_relay_install_pack._write_scheduled_task_wrapper', '17cf3840661d9e4b4e81f5f205c2826a23c53b6872fbacc60289e695d67fe33c'): ('direct_sync_install_pack', (), False, False),
    ('tools.direct_sync_relay_install_pack._write_scheduled_task_wrapper', '2634b961cb374edac1c11195c56ca20eef733f270ce64402962057be215527dc'): ('direct_sync_install_pack', (), False, False),
    ('tools.direct_sync_relay_install_pack._write_scheduled_task_wrapper', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('direct_sync_install_pack', (), False, False),
    ('tools.direct_sync_relay_operator._write_json_atomic', 'b762147a0575a9c219141d905cb359521ef4b0ae6053a719380332f546acf71a'): ('relay_operator_report', (), False, False),
    ('tools.direct_sync_relay_runner._build_delta_source_file', '6aad499e83584ad6f1ecebaf7e467534035e33ba928df911209156d0854acbd8'): ('raw_relay_storage', (), False, False),
    ('tools.direct_sync_relay_runner._scan_state_connect', 'b762147a0575a9c219141d905cb359521ef4b0ae6053a719380332f546acf71a'): ('raw_relay_storage', (), False, False),
    ('user_relay._write_json_atomic', 'd8d3aaabebc2d32ccbfa35401c2ac822563ff38c3a1b1687f4fa6a02d5972c81'): ('persistent_relay_status', (), False, False),
    ('user_relay.main', '773e572279ed42d5919b32486aa595bd2d6024a711e73dfc863581f28ecbda6a'): ('persistent_relay_status', ('persistent_relay_status',), True, False),
    ('user_relay.main', 'c1eed8eb9116f4c6c08f59df6c9e52f9df16e0befeda2b2646e2c7453ebbebc3'): ('persistent_relay_status', ('persistent_relay_status',), True, False),
}

INVENTORY_ALL_SOURCES_SENTINEL = "__INVENTORY_ALL_SOURCES__"
TRUSTED_CONTROL_PLANE_MUTATIONS: dict[str, str] = {}
CALLER_FENCED_MUTATIONS: dict[str, dict[str, tuple[str, ...] | str]] = {
    "auto_update._copy_prepared_bytes": {
        "callers": ("auto_update.copy_prepared_file", "auto_update.stage_prepared_copies"),
        "sources": ("auto_update_control",),
        "reason": "unchanged copy body is called only by the exact SYSTEM sink or approved feed staging probe",
    },
    "data_generation_guard._runtime_release": {
        "callers": ("data_generation_guard.record_before_data_open",),
        "sources": ("data_generation_marker",),
        "reason": "release-identity git reads run only inside the exact guarded data-open adapter",
    },
    "kmtech_shared.data_generation.record_generation": {
        "callers": ("data_generation_guard.record_before_data_open",),
        "sources": ("data_generation_marker",),
        "reason": "byte-pinned atomic marker writes run only inside the exact guarded CA adapter",
    },
    "kmtech_shared.runtime.init_runtime_schema": {
        "callers": (
            "producer_runtime_client.init_runtime_schema",
        ),
        "sources": ("producer_runtime_storage",),
        "reference_callers": (
            "direct_sync_push.init_relay_queue_schema",
            "producer_runtime_client._connect",
            "producer_runtime_client.init_runtime_schema",
        ),
        "reason": "byte-pinned runtime SQL is reached only through the guarded CA facades and their exact core callees",
    },
    "kmtech_shared.runtime._create_state": {
        "callers": (
            "kmtech_shared.runtime.disable_runtime_authority_in_transaction",
            "kmtech_shared.runtime.mark_runtime_operator_review_in_transaction",
            "producer_runtime_client._create_state",
        ),
        "sources": ("producer_runtime_storage",),
        "reference_callers": (
            "kmtech_shared.runtime.disable_runtime_authority_in_transaction",
            "kmtech_shared.runtime.mark_runtime_operator_review_in_transaction",
            "producer_runtime_client._create_state",
            "producer_runtime_client.ensure_runtime_authority",
            "producer_runtime_client.prepare_runtime_metadata",
        ),
        "reason": "byte-pinned runtime SQL is reached only through the guarded CA facades and their exact core callees",
    },
    "kmtech_shared.runtime._replace_expired_identity": {
        "callers": (
            "producer_runtime_client._replace_expired_identity",
        ),
        "sources": ("producer_runtime_storage",),
        "reference_callers": (
            "producer_runtime_client._operator_review_or_recover_exact_clone",
            "producer_runtime_client._replace_expired_identity",
            "producer_runtime_client.ensure_runtime_authority",
            "producer_runtime_client.expire_dead_fence_authority_in_transaction",
            "producer_runtime_client.prepare_runtime_metadata",
        ),
        "reason": "byte-pinned runtime SQL is reached only through the guarded CA facades and their exact core callees",
    },
    "kmtech_shared.runtime.apply_runtime_receipt_in_transaction": {
        "callers": (
            "producer_runtime_client.apply_runtime_receipt_in_transaction",
        ),
        "sources": ("producer_runtime_storage",),
        "reference_callers": (
            "direct_sync_push._set_relay_status",
            "producer_runtime_client.apply_runtime_receipt_in_transaction",
        ),
        "reason": "byte-pinned runtime SQL is reached only through the guarded CA facades and their exact core callees",
    },
    "kmtech_shared.runtime.mark_runtime_operator_review_in_transaction": {
        "callers": (
            "kmtech_shared.runtime.release_runtime_request_in_transaction",
            "producer_runtime_client.mark_runtime_operator_review_in_transaction",
        ),
        "sources": ("producer_runtime_storage",),
        "reference_callers": (
            "direct_sync_push._set_relay_status",
            "kmtech_shared.runtime.release_runtime_request_in_transaction",
            "producer_runtime_client.mark_runtime_operator_review_in_transaction",
        ),
        "reason": "byte-pinned runtime SQL is reached only through the guarded CA facades and their exact core callees",
    },
    "kmtech_shared.runtime.release_runtime_request_in_transaction": {
        "callers": (
            "producer_runtime_client.release_runtime_request_in_transaction",
        ),
        "sources": ("producer_runtime_storage",),
        "reference_callers": (
            "direct_sync_push._set_relay_status",
            "producer_runtime_client.release_runtime_request_in_transaction",
        ),
        "reason": "byte-pinned runtime SQL is reached only through the guarded CA facades and their exact core callees",
    },
    "kmtech_shared.runtime.disable_runtime_authority_in_transaction": {
        "callers": (
            "producer_runtime_client.disable_runtime_authority_in_transaction",
        ),
        "sources": ("producer_runtime_storage",),
        "reference_callers": (
            "direct_sync_push._set_relay_status",
            "producer_runtime_client.disable_runtime_authority_in_transaction",
        ),
        "reason": "byte-pinned runtime SQL is reached only through the guarded CA facades and their exact core callees",
    },
    "kmtech_shared.raster.RasterImage.save_png": {
        "callers": ("phs_label_workflow._save_raster_png",),
        "sources": ("phs_raster_png",),
        "reason": "byte-pinned shared method executes only beneath the exact fenced adapter",
    }
}
SCHEDULED_TASK_MUTATION_COMMANDS = (
    "Disable-ScheduledTask",
    "Enable-ScheduledTask",
    "Stop-ScheduledTask",
    "Start-ScheduledTask",
    "Register-ScheduledTask",
    "Unregister-ScheduledTask",
    "Set-ScheduledTask",
)
SERVICE_MUTATION_COMMANDS = (
    "New-Service",
    "Set-Service",
    "Remove-Service",
    "Start-Service",
    "Stop-Service",
    "Restart-Service",
    "Suspend-Service",
    "Resume-Service",
)
EXTERNAL_CONTROL_EXECUTABLES = (
    "schtasks",
    "schtasks.exe",
    "sc.exe",
    "systemctl",
    "launchctl",
)
EXTERNAL_PROCESS_CALLS = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.startfile",
        "os.system",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "subprocess.run",
    }
)
APPROVED_SCHEDULED_TASK_WRAPPERS = frozenset(
    {
        "Disable-ContainerScheduledTaskUnderWriterFence",
        "Enable-ContainerScheduledTaskUnderWriterFence",
        "Stop-ContainerScheduledTaskUnderWriterFence",
        "DisableAndStop-ContainerScheduledTaskUnderWriterFence",
        "Remove-ContainerScheduledTaskUnderWriterFence",
    }
)
SQL_MUTATION_PREFIXES = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "REPLACE",
    "CREATE",
    "ALTER",
    "DROP",
    "BEGIN",
    "VACUUM",
)
WRITE_MODES = frozenset({"w", "a", "x", "+"})
OS_FILE_MUTATORS = {
    "os.chmod",
    "os.chown",
    "os.ftruncate",
    "os.link",
    "os.makedirs",
    "os.mkdir",
    "os.open",
    "os.remove",
    "os.removedirs",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "os.symlink",
    "os.truncate",
    "os.unlink",
    "os.utime",
    "os.write",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copymode",
    "shutil.copystat",
    "shutil.copytree",
    "shutil.chown",
    "shutil.move",
    "shutil.rmtree",
}
REGISTRY_MUTATORS = {
    "winreg.CreateKey",
    "winreg.CreateKeyEx",
    "winreg.DeleteKey",
    "winreg.DeleteKeyEx",
    "winreg.DeleteValue",
    "winreg.SetValue",
    "winreg.SetValueEx",
}
PATH_METHOD_MUTATORS = {
    "hardlink_to",
    "mkdir",
    "rename",
    "replace",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
}
SQL_MUTATOR_METHODS = {"execute", "executemany", "executescript"}
NETWORK_MUTATOR_METHODS = {"post", "request"}
PATHLIKE_SYMBOL_SUFFIXES = (
    ".Path",
    ".PurePath",
    ".PurePosixPath",
    ".PureWindowsPath",
    ".PathLike",
)
PATHLIKE_FACTORY_TARGETS = {
    "pathlib.Path.cwd",
    "pathlib.Path.home",
}
PATHLIKE_ATTRIBUTE_NAMES = {"parent"}
PATHLIKE_RETURNING_METHODS = {
    "absolute",
    "expanduser",
    "joinpath",
    "resolve",
    "with_name",
    "with_stem",
    "with_suffix",
}

KNOWN_ROUTE_DEFS = (
    {
        "route_id": "gui_startup",
        "kind": "python",
        "start": "Container_Audit.main",
    },
    {
        "route_id": "event",
        "kind": "python",
        "start": "Container_Audit.ContainerAudit._log_event",
    },
    {
        "route_id": "persistent_relay",
        "kind": "python",
        "start": "user_relay.main",
    },
    {
        "route_id": "raw_runner",
        "kind": "python",
        "start": "tools.direct_sync_relay_runner.main",
    },
    {
        "route_id": "canonical_installer",
        "kind": "delegated_sources",
        "file": "INSTALL_CANONICAL_PORTABLE.ps1",
    },
)
class InventoryError(RuntimeError):
    pass


def _relative(path: Path) -> str:
    return path.as_posix()


def _module_name(path: Path) -> str:
    if path.name == "__init__.py":
        return ".".join(path.parent.parts)
    return ".".join(path.with_suffix("").parts)


def _assigned_string_literals(path: Path, variable_name: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(
            isinstance(target, ast.Name) and target.id == variable_name
            for target in targets
        ):
            continue
        return {
            child.value
            for child in ast.walk(node.value)
            if isinstance(child, ast.Constant) and isinstance(child.value, str)
        }
    raise InventoryError(f"shipping inventory variable is missing: {variable_name}")


def _discover_frozen_tool_paths(root: Path) -> set[Path]:
    update_contract = root / "update_service.py"
    frozen_builder = root / "tools" / "build_frozen_release_candidate.ps1"
    discovered: set[Path] = set()
    if update_contract.is_file():
        for value in _assigned_string_literals(
            update_contract,
            "REQUIRED_UPDATE_ARCHIVE_FILES",
        ):
            prefix = "Container_Audit/tools/"
            if value.startswith(prefix) and value.endswith(".py"):
                discovered.add(Path("tools") / value[len(prefix) :])
    if frozen_builder.is_file():
        source = frozen_builder.read_text(encoding="utf-8")
        discovered.update(
            Path(value.replace("\\", "/"))
            for value in re.findall(
                r'@\("[^"\r\n]+",\s*"(tools[/\\][^"\r\n]+\.py)"\)',
                source,
            )
        )
        for block in re.findall(
            r"Invoke-Checked\s+-FilePath[\s\S]*?-Arguments\s+@\(([\s\S]*?)\)\s+-Failure",
            source,
        ):
            if '"PyInstaller"' not in block or '"--onefile"' not in block:
                continue
            discovered.update(
                Path(value.replace("\\", "/"))
                for value in re.findall(r'"(tools[/\\][^"\r\n]+\.py)"', block)
            )
    missing = sorted(path.as_posix() for path in discovered if not (root / path).is_file())
    if missing:
        raise InventoryError("shipped frozen tool source is missing: " + ", ".join(missing))
    return discovered


def _discover_shipped_application_paths(root: Path) -> tuple[Path, ...]:
    """Mirror the builder's code-copy rules and include the pinned screen companion."""

    paths = {path.relative_to(root) for path in root.glob("*.py")}
    for package_name in (*SHIPPED_PACKAGE_DIRS, SCREEN_SHELL_DIR):
        package_root = root / package_name
        if package_root.is_dir():
            paths.update(path.relative_to(root) for path in package_root.rglob("*.py"))
    for relative in SHIPPED_PORTABLE_ENTRYPOINTS:
        if (root / relative).is_file():
            paths.add(relative)
    paths.update(_discover_frozen_tool_paths(root))
    return tuple(sorted(paths, key=lambda path: path.as_posix().casefold()))


def _discover_shipped_powershell_paths(root: Path) -> tuple[Path, ...]:
    """Derive shipped PowerShell sources from the portable builder contract."""

    builder = root / "tools" / "build_portable_release_candidate.py"
    if not builder.is_file():
        # Isolated detector fixtures intentionally omit the release builder.
        return POWERSHELL_PATHS
    tree = ast.parse(builder.read_text(encoding="utf-8"), filename=str(builder))
    install_assets: Any | None = None
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(
            isinstance(target, ast.Name) and target.id == "PORTABLE_INSTALL_ASSETS"
            for target in targets
        ):
            continue
        try:
            install_assets = ast.literal_eval(node.value)
        except (TypeError, ValueError, SyntaxError) as exc:
            raise InventoryError(
                "portable PowerShell shipping inventory is not static"
            ) from exc
        break
    if not isinstance(install_assets, (tuple, list)):
        raise InventoryError("portable install asset inventory is missing")
    discovered: set[Path] = set()
    for entry in install_assets:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise InventoryError("portable install asset entry is invalid")
        source = entry[0]
        if not isinstance(source, str) or not source.casefold().endswith(".ps1"):
            continue
        relative = Path(source.replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            raise InventoryError("portable PowerShell asset path is unsafe")
        discovered.add(relative)
    if not discovered:
        raise InventoryError("portable PowerShell shipping inventory is empty")
    missing = sorted(
        path.as_posix() for path in discovered if not (root / path).is_file()
    )
    if missing:
        raise InventoryError(
            "shipped PowerShell source is missing: " + ", ".join(missing)
        )
    return tuple(sorted(discovered, key=lambda path: path.as_posix().casefold()))


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _inventory_sha256(payload: dict[str, Any]) -> str:
    stable = dict(payload)
    stable.pop("inventory_sha256", None)
    return hashlib.sha256(_canonical_json_bytes(stable)).hexdigest()


def _string_literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _external_control_commands(text: str) -> list[str]:
    commands: list[str] = []
    for command in (*SCHEDULED_TASK_MUTATION_COMMANDS, *SERVICE_MUTATION_COMMANDS):
        if re.search(
            rf"(?i)(?<![A-Za-z0-9_-]){re.escape(command)}(?![A-Za-z0-9_-])",
            text,
        ):
            commands.append(command)
    for executable in EXTERNAL_CONTROL_EXECUTABLES:
        if re.search(
            rf"(?i)(?<![A-Za-z0-9_.-]){re.escape(executable)}(?![A-Za-z0-9_.-])",
            text,
        ):
            commands.append(executable)
    return sorted(set(commands), key=str.casefold)


def _external_control_commands_in_node(node: ast.AST) -> list[str]:
    commands: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            commands.update(_external_control_commands(child.value))
    return sorted(commands, key=str.casefold)


def _sql_literal(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None
        return "".join(parts)
    return None


def _is_write_mode(node: ast.AST | None) -> bool:
    mode = _string_literal(node)
    return bool(mode) and any(flag in mode for flag in WRITE_MODES)


def _looks_like_mutating_sql(node: ast.AST | None) -> bool:
    sql = _sql_literal(node)
    if sql is None:
        return False
    return sql.lstrip().upper().startswith(SQL_MUTATION_PREFIXES)


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _looks_like_open_flags(node: ast.AST | None) -> bool:
    if node is None:
        return False
    text = ast.unparse(node) if hasattr(ast, "unparse") else ""
    return any(flag in text for flag in ("O_CREAT", "O_EXCL", "O_WRONLY", "O_RDWR"))


def _writer_admission_source(
    node: ast.AST | None,
    *,
    resolve_callable,
    display_name,
) -> str:
    if not isinstance(node, ast.Call):
        return ""
    resolved = resolve_callable(node.func)
    if resolved != "writer_session_fence.writer_admission":
        return ""
    if not node.args:
        return ""
    return _string_literal(node.args[0]) or ""


def _is_pathlike_symbol(symbol: str) -> bool:
    return bool(symbol) and (
        symbol in {"pathlib.Path", "pathlib.PurePath"}
        or symbol.endswith(PATHLIKE_SYMBOL_SUFFIXES)
    )


def _annotation_is_pathlike(
    node: ast.AST | None,
    *,
    resolve_name,
) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        resolved = resolve_name(node.id)
        return _is_pathlike_symbol(resolved or node.id)
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            dotted = ".".join(reversed(parts))
            resolved = resolve_name(current.id)
            if resolved:
                suffix = ".".join(reversed(parts[:-1]))
                dotted = f"{resolved}.{suffix}" if suffix else resolved
            return _is_pathlike_symbol(dotted)
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _annotation_is_pathlike(node.left, resolve_name=resolve_name) or _annotation_is_pathlike(
            node.right,
            resolve_name=resolve_name,
        )
    if isinstance(node, ast.Subscript):
        return _annotation_is_pathlike(node.value, resolve_name=resolve_name) or _annotation_is_pathlike(
            node.slice,
            resolve_name=resolve_name,
        )
    if isinstance(node, ast.Tuple):
        return any(
            _annotation_is_pathlike(element, resolve_name=resolve_name)
            for element in node.elts
        )
    return False


def _iter_candidate_functions(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, (ast.Name, ast.Attribute)):
        return [node]
    if isinstance(node, ast.Lambda) and isinstance(node.body, ast.Call):
        return [node.body.func]
    return []


def _is_dunder_main_test(node: ast.AST) -> bool:
    if not isinstance(node, ast.Compare):
        return False
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return False
    return (
        isinstance(node.left, ast.Name)
        and node.left.id == "__name__"
        and isinstance(node.ops[0], ast.Eq)
        and _string_literal(node.comparators[0]) == "__main__"
    )


def _build_module_index(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(
            part in {"__pycache__", ".git", ".pytest_cache", ".ruff_cache"}
            for part in relative.parts
        ):
            continue
        result[_module_name(relative)] = relative
    return result


def _resolve_relative_module(
    current_module_name: str,
    imported_module: str | None,
    level: int,
) -> str:
    if level <= 0:
        return imported_module or ""
    parts = current_module_name.split(".")
    package_parts = parts[:-1]
    if level > len(package_parts) + 1:
        return imported_module or ""
    base = package_parts[: len(package_parts) - (level - 1)]
    if imported_module:
        return ".".join((*base, imported_module))
    return ".".join(base)


def _import_targets(
    node: ast.Import | ast.ImportFrom,
    *,
    module_name: str,
    module_index: dict[str, Path],
) -> list[str]:
    targets: set[str] = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name in module_index:
                targets.add(alias.name)
        return sorted(targets)
    base = _resolve_relative_module(module_name, node.module, node.level)
    if base in module_index:
        targets.add(base)
    for alias in node.names:
        candidate = f"{base}.{alias.name}" if base else alias.name
        if candidate in module_index:
            targets.add(candidate)
    return sorted(targets)


def _collect_import_closure(
    *,
    root: Path,
    entrypoint_modules: tuple[str, ...],
    module_index: dict[str, Path],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    parsed: dict[str, dict[str, Any]] = {}
    import_graph: dict[str, list[str]] = {}
    pending = deque(entrypoint_modules)
    while pending:
        module_name = pending.popleft()
        if module_name in parsed:
            continue
        relative_path = module_index.get(module_name)
        if relative_path is None:
            continue
        path = root / relative_path
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.update(
                    _import_targets(
                        node,
                        module_name=module_name,
                        module_index=module_index,
                    )
                )
        parsed[module_name] = {
            "module_name": module_name,
            "path": relative_path,
            "tree": tree,
            "source": source,
        }
        import_graph[module_name] = sorted(imports)
        for imported in sorted(imports):
            if imported not in parsed:
                pending.append(imported)
    return parsed, import_graph


class FunctionCollector(ast.NodeVisitor):
    def __init__(self, *, module_name: str) -> None:
        self.module_name = module_name
        self.scope_stack: list[str] = []
        self.class_stack: list[str] = []
        self.functions: dict[str, dict[str, Any]] = {}
        self.scope_symbols: dict[str, dict[str, str]] = defaultdict(dict)
        self.class_methods: dict[str, dict[str, str]] = defaultdict(dict)
        self.imports_by_scope: dict[str, dict[str, str]] = defaultdict(dict)

    def visit_Import(self, node: ast.Import) -> None:
        scope = self._scope_name()
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.imports_by_scope[scope][local] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        scope = self._scope_name()
        base = _resolve_relative_module(self.module_name, node.module, node.level)
        for alias in node.names:
            local = alias.asname or alias.name
            candidate = f"{base}.{alias.name}" if base else alias.name
            self.imports_by_scope[scope][local] = candidate

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_qualname = ".".join((self.module_name, *self.class_stack, node.name))
        self.scope_symbols[self._scope_name()][node.name] = class_qualname
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = ".".join(
            (self.module_name, *self.class_stack, *self.scope_stack, node.name)
        )
        self.scope_symbols[self._scope_name()][node.name] = qualname
        if self.class_stack:
            class_name = ".".join((self.module_name, *self.class_stack))
            self.class_methods[class_name][node.name] = qualname
        self.functions[qualname] = {
            "qualname": qualname,
            "name": node.name,
            "line": node.lineno,
            "class_qualname": ".".join((self.module_name, *self.class_stack))
            if self.class_stack
            else "",
            "decorator_sources": tuple(self._decorator_sources(node)),
            "default_callable_params": self._default_callable_params(node),
            "pathlike_params": tuple(self._pathlike_params(node)),
            "node": node,
        }
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def _scope_name(self) -> str:
        return ".".join((self.module_name, *self.class_stack, *self.scope_stack)).rstrip(".")

    def _decorator_sources(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[str]:
        result: list[str] = []
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            resolved = ""
            if isinstance(decorator.func, ast.Name):
                resolved = self._resolve_name_in_scope(
                    decorator.func.id,
                    self._scope_name(),
                )
            elif (
                isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
            ):
                base = self._resolve_name_in_scope(
                    decorator.func.value.id,
                    self._scope_name(),
                )
                if base:
                    resolved = f"{base}.{decorator.func.attr}"
            if resolved != "writer_session_fence.writer_sink":
                continue
            source = _string_literal(decorator.args[0])
            if source:
                result.append(source)
        return result

    def _resolve_name_in_scope(self, name: str, scope: str) -> str:
        current = scope
        while True:
            if name in self.scope_symbols.get(current, {}):
                return self.scope_symbols[current][name]
            if name in self.imports_by_scope.get(current, {}):
                return self.imports_by_scope[current][name]
            if not current or "." not in current:
                break
            current = current.rsplit(".", 1)[0]
        return self.imports_by_scope.get(self.module_name, {}).get(
            name,
            self.scope_symbols.get(self.module_name, {}).get(name, ""),
        )

    def _default_callable_params(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> dict[str, str]:
        params = [*node.args.posonlyargs, *node.args.args]
        result: dict[str, str] = {}
        if node.args.defaults:
            default_params = params[-len(node.args.defaults) :]
            for param, default in zip(default_params, node.args.defaults):
                resolved = self._resolve_default_callable(default)
                if resolved:
                    result[param.arg] = resolved
        for param, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            resolved = self._resolve_default_callable(default)
            if resolved:
                result[param.arg] = resolved
        return result

    def _pathlike_params(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[str]:
        params = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        result: list[str] = []
        for param in params:
            if _annotation_is_pathlike(
                param.annotation,
                resolve_name=lambda name, scope=self._scope_name(): self._resolve_name_in_scope(name, scope),
            ):
                result.append(param.arg)
        return result

    def _resolve_default_callable(self, node: ast.AST | None) -> str:
        if node is None:
            return ""
        scope = self._scope_name()
        if isinstance(node, ast.Name):
            return self._resolve_name_in_scope(node.id, scope)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            base = self._resolve_name_in_scope(node.value.id, scope)
            if base:
                return f"{base}.{node.attr}"
        return ""


class _NodeVisitor(ast.NodeVisitor):
    def __init__(
        self,
        *,
        collector: FunctionCollector,
        current_qualname: str,
        current_class: str,
        known_nodes: set[str],
        initial_import_scope: str,
        shell_kit_delegated: bool = False,
    ) -> None:
        self.collector = collector
        self.current_qualname = current_qualname
        self.current_class = current_class
        self.known_nodes = known_nodes
        self.current_function_info = collector.functions.get(current_qualname, {})
        self.import_scope_stack: list[str] = [initial_import_scope]
        self.calls: set[str] = set()
        self.mutation_sites: list[dict[str, Any]] = []
        self.directory_preparations: list[dict[str, Any]] = []
        self.directory_helper_references: list[int] = []
        self.atomic_helper_references: list[int] = []
        self.pathlike_refs: set[str] = set(
            self.current_function_info.get("pathlike_params", ())
        )
        self.writer_admission_stack: list[str] = []
        self.shell_kit_delegated = shell_kit_delegated

    def visit_Import(self, node: ast.Import) -> None:
        scope = self.import_scope_stack[-1]
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.collector.imports_by_scope[scope][local] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        scope = self.import_scope_stack[-1]
        base = _resolve_relative_module(
            self.collector.module_name,
            node.module,
            node.level,
        )
        for alias in node.names:
            local = alias.asname or alias.name
            candidate = f"{base}.{alias.name}" if base else alias.name
            self.collector.imports_by_scope[scope][local] = candidate

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_With(self, node: ast.With) -> None:
        self._visit_with_like(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with_like(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        if self._expr_is_pathlike(node.value):
            for target in node.targets:
                self._mark_pathlike_target(target)
        for target in node.targets:
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        if _annotation_is_pathlike(
            node.annotation,
            resolve_name=self._resolve_name_symbol,
        ) or self._expr_is_pathlike(node.value):
            self._mark_pathlike_target(node.target)
        self.visit(node.target)

    def visit_Call(self, node: ast.Call) -> None:
        resolved = self._resolve_callable(node.func)
        if resolved == DIRECTORY_PREPARATION_HELPER:
            if len(node.args) != 1 or node.keywords:
                raise InventoryError("directory preparation call shape changed")
            self.directory_preparations.append({
                "line": node.lineno,
                "argument_ast_sha256": _ast_sha256(node.args[0]),
                "writer_admission_sources": list(self.writer_admission_stack),
            })
        if resolved and resolved in self.known_nodes:
            self.calls.add(resolved)
        constructor = self._resolve_constructor(node.func)
        if constructor and constructor in self.known_nodes:
            self.calls.add(constructor)
        for value in [*node.args, *(keyword.value for keyword in node.keywords)]:
            for candidate in _iter_candidate_functions(value):
                callback = self._resolve_callable(candidate)
                if callback and callback in self.known_nodes:
                    self.calls.add(callback)
                callback_ctor = self._resolve_constructor(candidate)
                if callback_ctor and callback_ctor in self.known_nodes:
                    self.calls.add(callback_ctor)
        mutation = self._classify_mutation(node)
        if mutation is not None:
            self.mutation_sites.append(mutation)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and self._resolve_callable(node) == DIRECTORY_PREPARATION_HELPER:
            self.directory_helper_references.append(node.lineno)
        if isinstance(node.ctx, ast.Load):
            resolved = self._resolve_callable(node)
            if resolved == ATOMIC_REPLACEMENT_HELPER:
                self.atomic_helper_references.append(node.lineno)
            elif resolved == "atomic_replace._replace_once" and self.current_qualname != ATOMIC_REPLACEMENT_HELPER:
                raise InventoryError("atomic replacement private backend reference escaped its facade")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load) and self._resolve_callable(node) == DIRECTORY_PREPARATION_HELPER:
            self.directory_helper_references.append(node.lineno)
        if isinstance(node.ctx, ast.Load) and self._resolve_callable(node) == ATOMIC_REPLACEMENT_HELPER:
            self.atomic_helper_references.append(node.lineno)
        if (isinstance(node.ctx, ast.Load) and self._resolve_callable(node) == "atomic_replace._replace_once"
                and self.current_qualname != ATOMIC_REPLACEMENT_HELPER):
            raise InventoryError("atomic replacement private backend reference escaped its facade")
        self.generic_visit(node)

    def _scope_chain(self) -> list[str]:
        parts = self.current_qualname.split(".")
        chain = [".".join(parts[:index]) for index in range(len(parts), 0, -1)]
        chain.append(self.collector.module_name)
        return chain

    def _resolve_name_symbol(self, name: str) -> str:
        for scope in self._scope_chain():
            if name in self.collector.scope_symbols.get(scope, {}):
                return self.collector.scope_symbols[scope][name]
            if name in self.collector.imports_by_scope.get(scope, {}):
                return self.collector.imports_by_scope[scope][name]
        return ""

    def _visit_with_like(self, node: ast.With | ast.AsyncWith) -> None:
        admitted: list[str] = []
        for item in node.items:
            admission = _writer_admission_source(
                item.context_expr,
                resolve_callable=self._resolve_callable,
                display_name=self._display_name,
            )
            if (
                self.shell_kit_delegated
                and self.collector.module_name == SHELL_KIT_WRITE_MODULE
                and self.current_function_info.get("name") in SHELL_KIT_WRITE_SITES
                and isinstance(item.context_expr, ast.Call)
                and isinstance(item.context_expr.func, ast.Name)
                and item.context_expr.func.id == "_guard"
            ):
                admission = SHELL_KIT_WRITER_SOURCE
            if admission:
                admitted.append(admission)
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
        self.writer_admission_stack.extend(admitted)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            if admitted:
                del self.writer_admission_stack[-len(admitted) :]

    def _display_ref(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._display_ref(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def _mark_pathlike_target(self, node: ast.AST) -> None:
        if isinstance(node, (ast.Tuple, ast.List)):
            for element in node.elts:
                self._mark_pathlike_target(element)
            return
        ref = self._display_ref(node)
        if ref:
            self.pathlike_refs.add(ref)

    def _expr_is_pathlike(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            if node.id in self.pathlike_refs:
                return True
            return _is_pathlike_symbol(self._resolve_name_symbol(node.id))
        if isinstance(node, ast.Attribute):
            ref = self._display_ref(node)
            if ref in self.pathlike_refs:
                return True
            if node.attr in PATHLIKE_ATTRIBUTE_NAMES:
                return self._expr_is_pathlike(node.value)
            return False
        if isinstance(node, ast.Call):
            resolved = self._resolve_callable(node.func)
            if _is_pathlike_symbol(resolved) or resolved in PATHLIKE_FACTORY_TARGETS:
                return True
            if isinstance(node.func, ast.Attribute):
                return (
                    node.func.attr in PATHLIKE_RETURNING_METHODS
                    and self._expr_is_pathlike(node.func.value)
                )
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._expr_is_pathlike(node.left) or self._expr_is_pathlike(
                node.right
            )
        return False

    def _resolve_callable(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self._resolve_name_symbol(node.id)
        if isinstance(node, ast.Attribute):
            if (
                isinstance(node.value, ast.Name)
                and node.value.id in {"self", "cls"}
                and self.current_class
            ):
                return self.collector.class_methods.get(
                    self.current_class, {}
                ).get(node.attr, "")
            base = self._resolve_callable(node.value)
            return f"{base}.{node.attr}" if base else ""
        return ""

    def _resolve_constructor(self, node: ast.AST) -> str:
        target = self._resolve_callable(node)
        if not target:
            return ""
        init_name = f"{target}.__init__"
        return init_name if init_name in self.known_nodes else ""

    def _classify_mutation(self, node: ast.Call) -> dict[str, Any] | None:
        resolved = self._resolve_callable(node.func)
        if resolved == ATOMIC_REPLACEMENT_HELPER:
            def approved_keyword(keyword):
                if keyword.arg == "write_through":
                    return isinstance(keyword.value, ast.Constant) and type(keyword.value.value) is bool
                # The same relay sink may supply its caller's bounded budget.
                # No other caller, option or destination shape is admitted.
                return (self.current_qualname == "user_relay._write_json_atomic"
                        and keyword.arg == "deadline" and isinstance(keyword.value, ast.Name)
                        and keyword.value.id == "deadline")
            if len(node.args) != 2 or any(not approved_keyword(keyword) for keyword in node.keywords):
                raise InventoryError("atomic replacement call shape changed")
            return self._mutation_record(node, resolved, "filesystem")
        if resolved in EXTERNAL_PROCESS_CALLS:
            return self._mutation_record(
                node,
                resolved,
                "external_process",
                external_control_commands=_external_control_commands_in_node(node),
            )
        if resolved in REGISTRY_MUTATORS:
            return self._mutation_record(node, resolved, "registry")
        if resolved in OS_FILE_MUTATORS:
            if resolved == "os.open":
                flags_node = node.args[1] if len(node.args) > 1 else None
                if not _looks_like_open_flags(flags_node):
                    return None
            return self._mutation_record(node, resolved, "filesystem")
        sql_arg = node.args[0] if node.args else None
        if (
            resolved.endswith(".execute")
            or resolved.endswith(".executemany")
            or resolved.endswith(".executescript")
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in SQL_MUTATOR_METHODS
            )
        ) and _looks_like_mutating_sql(sql_arg):
            return self._mutation_record(
                node,
                resolved or self._display_name(node.func),
                "sqlite",
            )
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            mode_node = (
                node.args[1] if len(node.args) > 1 else _keyword_value(node, "mode")
            )
            if _is_write_mode(mode_node):
                return self._mutation_record(node, "open", "filesystem")
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in NETWORK_MUTATOR_METHODS:
                return self._mutation_record(
                    node,
                    self._display_name(node.func),
                    "network",
                )
            if node.func.attr == "open":
                mode_node = (
                    node.args[0] if node.args else _keyword_value(node, "mode")
                )
                if _is_write_mode(mode_node) and self._expr_is_pathlike(node.func.value):
                    return self._mutation_record(
                        node, self._display_name(node.func), "filesystem"
                    )
            if (
                node.func.attr in PATH_METHOD_MUTATORS
                and self._expr_is_pathlike(node.func.value)
            ):
                return self._mutation_record(
                    node, self._display_name(node.func), "filesystem"
                )
        return None

    def _display_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._display_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def _mutation_record(
        self,
        node: ast.Call,
        operation: str,
        category: str,
        *,
        external_control_commands: list[str] | None = None,
    ) -> dict[str, Any]:
        record = {
            "line": node.lineno,
            "operation": operation,
            "category": category,
            "writer_admission_sources": sorted(set(self.writer_admission_stack)),
        }
        if category == "external_process":
            record["external_control_commands"] = sorted(
                set(external_control_commands or ()),
                key=str.casefold,
            )
        return record


def _module_import_edges(
    *,
    module_name: str,
    import_graph: dict[str, list[str]],
    known_nodes: set[str],
) -> list[str]:
    return sorted(
        target
        for imported in import_graph.get(module_name, [])
        if (target := f"{imported}.__module__") in known_nodes
    )


def _analyze_module_node(
    *,
    module_name: str,
    tree: ast.Module,
    collector: FunctionCollector,
    import_graph: dict[str, list[str]],
    known_nodes: set[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    module_visitor = _NodeVisitor(
        collector=collector,
        current_qualname=f"{module_name}.__module__",
        current_class="",
        known_nodes=known_nodes,
        initial_import_scope=module_name,
    )
    file_entry_visitor = _NodeVisitor(
        collector=collector,
        current_qualname=f"{module_name}.__file_entry__",
        current_class="",
        known_nodes=known_nodes,
        initial_import_scope=module_name,
    )
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.If) and _is_dunder_main_test(node.test):
            for child in [*node.body, *node.orelse]:
                file_entry_visitor.visit(child)
            continue
        module_visitor.visit(node)
    module_calls = sorted(
        set(
            _module_import_edges(
                module_name=module_name,
                import_graph=import_graph,
                known_nodes=known_nodes,
            )
        )
        | module_visitor.calls
    )
    file_entry_calls = sorted(
        set(module_calls) | {f"{module_name}.__module__"} | file_entry_visitor.calls
    )
    return (
        {
            "calls": module_calls,
            "mutation_sites": module_visitor.mutation_sites,
            "directory_preparations": module_visitor.directory_preparations,
            "directory_helper_references": module_visitor.directory_helper_references,
            "atomic_helper_references": module_visitor.atomic_helper_references,
        },
        {
            "calls": file_entry_calls,
            "mutation_sites": file_entry_visitor.mutation_sites,
            "directory_preparations": file_entry_visitor.directory_preparations,
            "directory_helper_references": file_entry_visitor.directory_helper_references,
            "atomic_helper_references": file_entry_visitor.atomic_helper_references,
        },
    )


def _ast_sha256(node: ast.AST) -> str:
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode("utf-8")).hexdigest()


def _forward_atomic_replacements(parsed_modules, node_analysis):
    """Keep each publication effect on its original caller/admission, never on a shared sink."""
    callers = []
    for caller, details in node_analysis.items():
        sites = [site for site in details["mutation_sites"] if site["operation"] == ATOMIC_REPLACEMENT_HELPER]
        if sorted(details["atomic_helper_references"]) != sorted(site["line"] for site in sites):
            raise InventoryError("atomic replacement non-call reference: " + caller)
        callers.extend({"caller": caller, **site} for site in sites)
    helper = parsed_modules.get("atomic_replace")
    if helper is None:
        if callers:
            raise InventoryError("atomic replacement facade is missing")
        return
    if _ast_sha256(helper["tree"]) != ATOMIC_REPLACEMENT_MODULE_AST_SHA256:
        raise InventoryError("atomic replacement facade body changed")
    # Every facade call remains a directly inventoried filesystem mutation above.
    # Only the exact backend/module effects are projected; no caller fence is removed.
    for name, details in node_analysis.items():
        if name.startswith("atomic_replace."):
            details["mutation_sites"] = []
    node_analysis[ATOMIC_REPLACEMENT_HELPER]["atomic_replacement_forwarding"] = sorted(callers, key=lambda row: (row["caller"], row["line"]))


def _forward_directory_preparations(
    collectors: dict[str, FunctionCollector],
    node_analysis: dict[str, dict[str, Any]],
) -> None:
    """Attribute the unchanged directory-only helper to its exact b82 callers.

    This transfers directory effects, not permission to write business files.
    The one pre-bootstrap preparation remains outside writer admission, as before.
    """
    if DIRECTORY_PREPARATION_HELPER not in node_analysis:
        return
    helper = collectors["storage_policy"].functions[DIRECTORY_PREPARATION_HELPER]
    if _ast_sha256(helper["node"]) != DIRECTORY_PREPARATION_HELPER_AST_SHA256:
        raise InventoryError("directory preparation helper body changed")
    helper_details = node_analysis[DIRECTORY_PREPARATION_HELPER]
    if len(helper_details["mutation_sites"]) != 1:
        raise InventoryError("directory preparation helper must have exactly one mkdir")
    functions = {name: info for collector in collectors.values() for name, info in collector.functions.items()}
    seen: set[tuple[str, str]] = set()
    forwarded: list[dict[str, Any]] = []
    for caller, details in sorted(node_analysis.items()):
        calls = details["directory_preparations"]
        if sorted(details["directory_helper_references"]) != sorted(call["line"] for call in calls):
            raise InventoryError(f"directory preparation non-call reference: {caller}")
        for call in calls:
            key = (caller, call["argument_ast_sha256"])
            if key not in DIRECTORY_PREPARATION_CALLS or key in seen:
                raise InventoryError(f"unregistered directory preparation: {caller}")
            source, admissions, probe_only, report_only = DIRECTORY_PREPARATION_CALLS[key]
            info = functions[caller]
            sources = info["decorator_sources"]
            flags = {"probe_only": False, "report_only": False}
            for decorator in info["node"].decorator_list:
                if not isinstance(decorator, ast.Call) or not decorator.args or not sources:
                    continue
                if _string_literal(decorator.args[0]) != sources[0]:
                    continue
                for keyword in decorator.keywords:
                    if keyword.arg in flags:
                        if not isinstance(keyword.value, ast.Constant) or type(keyword.value.value) is not bool:
                            raise InventoryError(f"directory preparation decorator changed: {caller}")
                        flags[keyword.arg] = keyword.value.value
            if (
                tuple(call["writer_admission_sources"]) != admissions
                or (sources[0] if sources else (admissions[0] if admissions else "")) != source
                or (flags["probe_only"], flags["report_only"]) != (probe_only, report_only)
            ):
                raise InventoryError(f"directory preparation admission changed: {caller}")
            seen.add(key)
            classification = (
                "writer_admission" if admissions else
                "report_only_metadata" if report_only else
                "probe_only" if probe_only else
                "decorator" if source else
                "pre_admission_directory_preparation"
            )
            forwarded.append({
                "caller": caller, **call,
                "source": source, "classification": classification,
                "probe_only": probe_only, "report_only": report_only,
            })
            if source:
                # Preserve the old mkdir's caller fence; file mutations stay separate.
                details["mutation_sites"].append({
                    **helper_details["mutation_sites"][0],
                    "line": call["line"],
                    "writer_admission_sources": list(admissions),
                    "directory_preparation_helper": DIRECTORY_PREPARATION_HELPER,
                })
    if seen != set(DIRECTORY_PREPARATION_CALLS):
        raise InventoryError("directory preparation coverage must preserve the 33 b82 sites and exact instance report preparation")
    helper_details["mutation_sites"] = []
    helper_details["directory_preparation_forwarding"] = forwarded


def _analyze_closure(
    *,
    parsed_modules: dict[str, dict[str, Any]],
    import_graph: dict[str, list[str]],
    shell_kit_delegated: bool = False,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, list[str]],
    dict[str, str],
    dict[str, str],
]:
    collectors: dict[str, FunctionCollector] = {}
    known_nodes: set[str] = set()
    sink_sources: dict[str, str] = {}
    sink_marker_kinds: dict[str, str] = {}

    for module_name, payload in parsed_modules.items():
        collector = FunctionCollector(module_name=module_name)
        collector.visit(payload["tree"])
        payload["collector"] = collector
        collectors[module_name] = collector
        known_nodes.add(f"{module_name}.__module__")
        known_nodes.add(f"{module_name}.__file_entry__")
        known_nodes.update(collector.functions)
        for qualname, info in collector.functions.items():
            if not info["decorator_sources"]:
                continue
            function_node = info["node"]
            if isinstance(function_node, ast.AsyncFunctionDef) or any(
                isinstance(candidate, (ast.Yield, ast.YieldFrom))
                for candidate in ast.walk(function_node)
            ):
                raise InventoryError(
                    f"writer sinks must be synchronous non-generator functions: {qualname}"
                )
            if len(info["decorator_sources"]) != 1:
                raise InventoryError(
                    f"writer sink decorators must be unique: {qualname}"
                )
            sink_sources[qualname] = info["decorator_sources"][0]
            sink_marker_kinds[qualname] = "decorator"

    node_analysis: dict[str, dict[str, Any]] = {}
    for module_name, payload in parsed_modules.items():
        collector = collectors[module_name]
        for qualname, info in collector.functions.items():
            visitor = _NodeVisitor(
                collector=collector,
                current_qualname=qualname,
                current_class=info["class_qualname"],
                known_nodes=known_nodes,
                initial_import_scope=qualname.rsplit(".", 1)[0],
                shell_kit_delegated=shell_kit_delegated,
            )
            for child in info["node"].body:
                visitor.visit(child)
            node_analysis[qualname] = {
                "calls": sorted(visitor.calls),
                "mutation_sites": visitor.mutation_sites,
                "directory_preparations": visitor.directory_preparations,
                "directory_helper_references": visitor.directory_helper_references,
                "atomic_helper_references": visitor.atomic_helper_references,
            }
        module_node, file_entry_node = _analyze_module_node(
            module_name=module_name,
            tree=payload["tree"],
            collector=collector,
            import_graph=import_graph,
            known_nodes=known_nodes,
        )
        node_analysis[f"{module_name}.__module__"] = module_node
        node_analysis[f"{module_name}.__file_entry__"] = file_entry_node

    _forward_atomic_replacements(parsed_modules, node_analysis)
    _forward_directory_preparations(collectors, node_analysis)

    for qualname, details in node_analysis.items():
        if qualname in sink_sources or not details["mutation_sites"]:
            continue
        admission_sources = {
            source
            for site in details["mutation_sites"]
            for source in site["writer_admission_sources"]
        }
        if not admission_sources:
            continue
        if any(not site["writer_admission_sources"] for site in details["mutation_sites"]):
            continue
        if len(admission_sources) != 1:
            raise InventoryError(
                f"writer admission sources must be unique per direct mutator: {qualname}"
            )
        sink_sources[qualname] = next(iter(admission_sources))
        sink_marker_kinds[qualname] = "writer_admission"

    call_graph = {
        qualname: sorted(set(details["calls"]))
        for qualname, details in sorted(node_analysis.items())
    }
    return node_analysis, call_graph, sink_sources, sink_marker_kinds


def _normalize_start_names(call_graph: dict[str, list[str]]) -> list[str]:
    file_entrypoints = {
        node for node in call_graph if node.endswith(".__file_entry__")
    }
    audited_route_starts = {
        str(route["start"])
        for route in KNOWN_ROUTE_DEFS
        if route["kind"] == "python" and str(route["start"]) in call_graph
    }
    return sorted(file_entrypoints | audited_route_starts)


def _coverage_states(
    *,
    starts: list[str],
    call_graph: dict[str, list[str]],
    sink_nodes: set[str],
) -> tuple[dict[str, dict[str, set[str]]], dict[tuple[str, str], tuple[str, str] | None]]:
    coverage: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"covered_entrypoints": set(), "unsunk_entrypoints": set()}
    )
    predecessor: dict[tuple[str, str], tuple[str, str] | None] = {}
    queue: deque[tuple[str, str, bool]] = deque()
    seen: set[tuple[str, str, bool]] = set()

    for start in starts:
        start_sunk = start in sink_nodes
        queue.append((start, start, start_sunk))
        if not start_sunk:
            predecessor[(start, start)] = None

    while queue:
        node, start, sunk = queue.popleft()
        state = (node, start, sunk)
        if state in seen:
            continue
        seen.add(state)
        if sunk:
            coverage[node]["covered_entrypoints"].add(start)
        else:
            coverage[node]["unsunk_entrypoints"].add(start)
        for target in call_graph.get(node, []):
            next_sunk = sunk or target in sink_nodes
            next_state = (target, start, next_sunk)
            if next_state in seen:
                continue
            if not next_sunk and (target, start) not in predecessor:
                predecessor[(target, start)] = (node, start)
            queue.append(next_state)
    return coverage, predecessor


def _reconstruct_unsunk_path(
    *,
    node: str,
    start: str,
    predecessor: dict[tuple[str, str], tuple[str, str] | None],
) -> list[str]:
    path = [node]
    current = predecessor.get((node, start))
    while current is not None:
        path.append(current[0])
        current = predecessor.get(current)
    path.reverse()
    return path


def _reachable_sources(
    start: str,
    *,
    call_graph: dict[str, list[str]],
    sink_sources: dict[str, str],
) -> list[str]:
    queue = deque([start])
    seen: set[str] = set()
    sources: set[str] = set()
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        if current in sink_sources:
            sources.add(sink_sources[current])
        for target in call_graph.get(current, []):
            if target not in seen:
                queue.append(target)
    return sorted(sources)


def _sink_rows(
    *,
    parsed_modules: dict[str, dict[str, Any]],
    node_analysis: dict[str, dict[str, Any]],
    sink_sources: dict[str, str],
    sink_marker_kinds: dict[str, str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for module_name, payload in parsed_modules.items():
        collector: FunctionCollector = payload["collector"]
        for qualname, info in sorted(collector.functions.items()):
            if qualname not in sink_sources:
                continue
            rows.append(
                {
                    "source": sink_sources[qualname],
                    "function": qualname,
                    "marker_kind": sink_marker_kinds.get(qualname, "decorator"),
                    "file": _relative(payload["path"]),
                    "line": info["line"],
                    "direct_mutation_site_count": len(
                        node_analysis[qualname]["mutation_sites"]
                    ),
                }
            )
    rows.sort(key=lambda row: (row["source"], row["function"]))
    return rows


def _closure_mutation_rows(
    *,
    parsed_modules: dict[str, dict[str, Any]],
    node_analysis: dict[str, dict[str, Any]],
    coverage: dict[str, dict[str, set[str]]],
    predecessor: dict[tuple[str, str], tuple[str, str] | None],
    sink_sources: dict[str, str],
    call_graph: dict[str, list[str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    module_names = sorted(parsed_modules, key=len, reverse=True)
    callers_by_node: dict[str, list[str]] = defaultdict(list)
    for caller, callees in call_graph.items():
        for callee in callees:
            callers_by_node[callee].append(caller)
    for qualname, details in sorted(node_analysis.items()):
        if not details["mutation_sites"]:
            continue
        covered = sorted(coverage.get(qualname, {}).get("covered_entrypoints", set()))
        unsunk = sorted(coverage.get(qualname, {}).get("unsunk_entrypoints", set()))
        reachable_entrypoints = sorted(set(covered) | set(unsunk))
        if qualname.endswith((".__module__", ".__file_entry__")):
            module_name = qualname.rsplit(".", 1)[0]
            relative_path = _relative(parsed_modules[module_name]["path"])
            line = 1
            kind = "module"
            decorated_source = ""
        else:
            module_name = next(
                name
                for name in module_names
                if qualname == name or qualname.startswith(f"{name}.")
            )
            info = parsed_modules[module_name]["collector"].functions[qualname]
            relative_path = _relative(parsed_modules[module_name]["path"])
            line = info["line"]
            kind = "function"
            decorated_source = sink_sources.get(qualname, "")
        direct_callers = sorted(set(callers_by_node.get(qualname, [])))
        caller_guard_sources = sorted(
            {
                sink_sources[caller]
                for caller in direct_callers
                if caller in sink_sources
            }
        )
        caller_contract = CALLER_FENCED_MUTATIONS.get(qualname)
        caller_contract_matches = bool(caller_contract) and (
            direct_callers == list(caller_contract["callers"])
            and caller_guard_sources == list(caller_contract["sources"])
        )
        trust_reason = TRUSTED_CONTROL_PLANE_MUTATIONS.get(qualname, "")
        if decorated_source:
            coverage_status = "covered"
        elif caller_contract_matches:
            coverage_status = "covered"
        elif trust_reason:
            coverage_status = "trusted_control_plane"
        else:
            coverage_status = "uncovered"
        rows.append(
            {
                "node": qualname,
                "kind": kind,
                "file": relative_path,
                "line": line,
                "decorated_source": decorated_source,
                "direct_callers": direct_callers,
                "caller_guard_sources": (
                    caller_guard_sources if caller_contract_matches else []
                ),
                "caller_guard_reason": (
                    str(caller_contract["reason"])
                    if caller_contract_matches and caller_contract is not None
                    else ""
                ),
                "trust_reason": trust_reason,
                "reachable_entrypoints": reachable_entrypoints,
                "reachable_from_product_entrypoint": bool(reachable_entrypoints),
                "covered_entrypoints": covered,
                "unsunk_entrypoints": unsunk,
                "coverage_status": coverage_status,
                "mutation_sites": details["mutation_sites"],
                "unsunk_paths": [
                    {
                        "entrypoint": start,
                        "path": _reconstruct_unsunk_path(
                            node=qualname,
                            start=start,
                            predecessor=predecessor,
                        ),
                    }
                    for start in unsunk
                ],
            }
        )
    rows.sort(key=lambda row: (row["file"], row["line"], row["node"]))
    return rows


class _NamedCallSiteCollector(ast.NodeVisitor):
    def __init__(self, module_name: str, callable_name: str) -> None:
        self.module_name = module_name
        self.callable_name = callable_name
        self.scope: list[str] = []
        self.sites: list[dict[str, Any]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name == self.callable_name:
            caller = (
                f"{self.module_name}." + ".".join(self.scope)
                if self.scope
                else f"{self.module_name}.__module__"
            )
            self.sites.append({"caller": caller, "line": node.lineno})
        self.generic_visit(node)


class _ExternalControlLiteralCollector(ast.NodeVisitor):
    def __init__(self, module_name: str) -> None:
        self.module_name = module_name
        self.scope: list[str] = []
        self.sites: list[dict[str, Any]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, str):
            return
        commands = _external_control_commands(node.value)
        if not commands:
            return
        function = (
            f"{self.module_name}." + ".".join(self.scope)
            if self.scope
            else f"{self.module_name}.__module__"
        )
        self.sites.append(
            {
                "function": function,
                "line": node.lineno,
                "commands": commands,
            }
        )


def _collect_python_external_control_commands(
    parsed_modules: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    sites: list[dict[str, Any]] = []
    for module_name, payload in parsed_modules.items():
        collector = _ExternalControlLiteralCollector(module_name)
        collector.visit(payload["tree"])
        sites.extend(
            {
                "file": _relative(payload["path"]),
                **site,
            }
            for site in collector.sites
        )
    sites.sort(key=lambda site: (site["file"], site["line"], site["function"]))
    return {
        "commands": sorted(
            {
                command
                for site in sites
                for command in site["commands"]
            },
            key=str.casefold,
        ),
        "literal_sites": sites,
    }


def _caller_fence_reference_failures(
    parsed_modules: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for target, contract in sorted(CALLER_FENCED_MUTATIONS.items()):
        callable_name = target.rsplit(".", 1)[-1]
        sites: list[dict[str, Any]] = []
        for module_name, payload in parsed_modules.items():
            collector = _NamedCallSiteCollector(module_name, callable_name)
            collector.visit(payload["tree"])
            sites.extend(
                {
                    "file": _relative(payload["path"]),
                    **site,
                }
                for site in collector.sites
            )
        # Runtime core and compatibility facades intentionally share short names.
        # Keep an exact lexical reference set in addition to resolved direct callers.
        expected_callers = set(contract.get("reference_callers", contract["callers"]))
        actual_callers = {str(site["caller"]) for site in sites}
        if actual_callers != expected_callers:
            failures.append(
                {
                    "target": target,
                    "expected_callers": sorted(expected_callers),
                    "actual_callers": sorted(actual_callers),
                    "call_sites": sorted(
                        sites,
                        key=lambda site: (site["file"], site["line"]),
                    ),
                }
            )
    return failures


def _extract_ps_delegated_sources(lines: list[str]) -> list[str]:
    if any(
        "$canonicalWriterFenceDelegatedSources = [Object[]]@($sourceWriterInventory.writer_sink_sources)"
        in line
        for line in lines
    ):
        return [INVENTORY_ALL_SOURCES_SENTINEL]
    delegated: list[str] = []
    collecting = False
    for line in lines:
        if (
            "-DelegatedSources @(" in line
            or "$canonicalWriterFenceDelegatedSources = @(" in line
        ):
            collecting = True
            continue
        if collecting:
            if ")" in line:
                break
            delegated.extend(
                match.group(1) for match in re.finditer(r"'([^']+)'", line)
            )
    return sorted(delegated)


def _powershell_code_brace_delta(line: str) -> int:
    depth = 0
    quote = ""
    escaped = False
    for character in line:
        if escaped:
            escaped = False
            continue
        if character == "`":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
            continue
        if character == "#":
            break
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
    return depth


def _powershell_function_ranges(lines: list[str]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^\s*function\s+([A-Za-z0-9_-]+)\b", lines[index])
        if match is None:
            index += 1
            continue
        start = index
        depth = 0
        opened = False
        end = index
        while end < len(lines):
            delta = _powershell_code_brace_delta(lines[end])
            if delta > 0:
                opened = True
            depth += delta
            if opened and depth == 0:
                break
            end += 1
        if not opened or end >= len(lines):
            raise InventoryError(
                f"PowerShell function boundary is invalid: {match.group(1)}"
            )
        ranges.append(
            {
                "name": match.group(1),
                "start": start + 1,
                "end": end + 1,
                "lines": lines[start : end + 1],
            }
        )
        index = end + 1
    return ranges


def _powershell_code_only(line: str) -> str:
    output: list[str] = []
    quote = ""
    escaped = False
    for character in line:
        if escaped:
            escaped = False
            output.append(" ")
            continue
        if character == "`":
            escaped = True
            output.append(" ")
            continue
        if quote:
            if character == quote:
                quote = ""
            output.append(" ")
            continue
        if character in {"'", '"'}:
            quote = character
            output.append(" ")
            continue
        if character == "#":
            break
        output.append(character)
    return "".join(output)


def _powershell_command_present(code: str, command: str) -> bool:
    return bool(
        re.search(
            rf"(?i)(?<![A-Za-z0-9_-]){re.escape(command)}(?![A-Za-z0-9_-])",
            code,
        )
    )


def _powershell_assignment_key(code: str, start: int, end: int) -> bool:
    if not re.match(r"\s*=(?!=)", code[end:]):
        return False
    # An attached '=' belongs to the token; spaced '=' can be a command argument.
    if code[end:].startswith("="):
        return True
    braces: list[tuple[bool, int]] = []
    for index, character in enumerate(code[:start]):
        if character == "{":
            braces.append((index > 0 and code[index - 1] == "@", index))
        elif character == "}" and braces:
            braces.pop()
    if not braces or not braces[-1][0]:
        return False
    boundary = max(braces[-1][1], code.rfind(";", 0, start), code.rfind("\n", 0, start))
    return not code[boundary + 1 : start].strip()


def _powershell_statement_command(code: str, command_pattern: str) -> re.Match[str] | None:
    return next(
        (match for match in re.finditer(
            rf"(?i)(?:^|[;{{}}|()]\s*)({command_pattern})(?![A-Za-z0-9_-])",
            code,
        ) if not _powershell_assignment_key(code, match.start(1), match.end(1))),
        None,
    )


def _powershell_function_at_line(
    function_ranges: list[dict[str, Any]], line: int
) -> dict[str, Any] | None:
    return next(
        (
            candidate
            for candidate in function_ranges
            if candidate["start"] <= line <= candidate["end"]
        ),
        None,
    )


def _powershell_entry_guard(
    relative_path: Path,
    lines: list[str],
    function_ranges: list[dict[str, Any]],
) -> dict[str, Any]:
    contract = POWERSHELL_ENTRYPOINT_GUARDS.get(relative_path)
    if contract is None:
        return {
            "required": False,
            "guard_name": "",
            "guard_kind": "",
            "guard_line": None,
            "release_name": "",
            "release_line": None,
            "lifetime_end_line": None,
            "valid": False,
            "writer_source": "",
        }
    entry_guard = str(contract["entry_guard"])
    guard_lines = [
        index
        for index, line in enumerate(lines, start=1)
        if _powershell_command_present(_powershell_code_only(line), entry_guard)
        and _powershell_function_at_line(function_ranges, index) is None
        and not re.match(r"^\s*function\b", line, re.IGNORECASE)
    ]
    release_guard = str(contract.get("release_guard", ""))
    release_lines = (
        [
            index
            for index, line in enumerate(lines, start=1)
            if _powershell_command_present(_powershell_code_only(line), release_guard)
            and _powershell_function_at_line(function_ranges, index) is None
            and not re.match(r"^\s*function\b", line, re.IGNORECASE)
        ]
        if release_guard
        else []
    )
    valid = len(guard_lines) == 1
    if release_guard:
        valid = bool(
            valid
            and len(release_lines) == 1
            and release_lines[0] > guard_lines[0]
        )
    internal_function_name = str(contract.get("internal_guard_function", ""))
    internal_guard = str(contract.get("internal_guard", ""))
    prelaunch_boundary = str(contract.get("prelaunch_boundary", ""))
    if internal_function_name:
        internal_function = next(
            (
                candidate
                for candidate in function_ranges
                if candidate["name"] == internal_function_name
            ),
            None,
        )
        if internal_function is None:
            valid = False
        else:
            function_lines = list(internal_function["lines"])
            internal_positions = [
                index
                for index, line in enumerate(function_lines)
                if _powershell_command_present(
                    _powershell_code_only(line), internal_guard
                )
            ]
            prelaunch_positions = [
                index
                for index, line in enumerate(function_lines)
                if _powershell_command_present(
                    _powershell_code_only(line), prelaunch_boundary
                )
            ]
            valid = bool(
                valid
                and len(internal_positions) >= 2
                and len(prelaunch_positions) == 1
                and internal_positions[0]
                < prelaunch_positions[0]
                < internal_positions[-1]
            )
    return {
        "required": True,
        "guard_name": entry_guard,
        "guard_kind": str(contract["guard_kind"]),
        "guard_line": guard_lines[0] if guard_lines else None,
        "release_name": release_guard,
        "release_line": release_lines[0] if len(release_lines) == 1 else None,
        "lifetime_end_line": (
            release_lines[0] if len(release_lines) == 1 else len(lines) + 1
        ),
        "valid": valid,
        "writer_source": str(contract.get("writer_source", "")),
    }


def _powershell_line_in_guard_lifetime(
    entry_guard: dict[str, Any], line: int
) -> bool:
    """Return whether a top-level line is strictly inside the held lifetime."""
    guard_line = entry_guard.get("guard_line")
    lifetime_end_line = entry_guard.get("lifetime_end_line")
    return bool(
        entry_guard.get("valid")
        and isinstance(guard_line, int)
        and isinstance(lifetime_end_line, int)
        and guard_line < line < lifetime_end_line
    )


def _powershell_mode_ranges(
    lines: list[str], function_ranges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Find exact top-level ``if ($Mode -ceq '<mode>')`` blocks."""
    ranges: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        if _powershell_function_at_line(function_ranges, index) is not None:
            continue
        match = re.match(
            r'''(?i)^\s*if\s*\(\s*\$Mode\s+-ceq\s*(['"])([A-Za-z0-9_-]+)\1\s*\)\s*\{''',
            line,
        )
        if match is None:
            continue
        depth = 0
        opened = False
        end = index
        while end <= len(lines):
            delta = _powershell_code_brace_delta(lines[end - 1])
            if delta > 0:
                opened = True
            depth += delta
            if opened and depth == 0:
                break
            end += 1
        if not opened or end > len(lines):
            raise InventoryError(
                f"PowerShell mode boundary is invalid: {match.group(2)}"
            )
        ranges.append(
            {
                "mode": match.group(2).casefold(),
                "start": index,
                "end": end,
            }
        )
    return ranges


def _powershell_local_authority_region(
    function: dict[str, Any], entry_guard: dict[str, Any],
) -> dict[str, int] | None:
    """Recognize an unconditional acquisition followed immediately by try/finally.

    This is a deliberately restricted syntax proof, not a function-name exemption.
    Ambiguous control flow, rebinding, early release, and incomplete cleanup earn
    no local protection. Admission, when present, must have its own nested lifetime.
    """
    if not entry_guard.get("valid") or entry_guard.get("guard_kind") != "session_authority":
        return None
    raw = list(function["lines"])
    if any(re.search(r"@['\"]|['\"]@|<#|#>", line) for line in raw):
        return None  # Multi-line literal contents are not executable statements.
    for line in raw:
        quote = ""
        escaped = False
        for character in line:
            if escaped:
                escaped = False
            elif character == "`":
                escaped = True
            elif quote:
                if character == quote:
                    quote = ""
            elif character in {"'", '"'}:
                quote = character
            elif character == "#":
                break
        if quote:
            return None  # Ordinary quoted literals can also span physical lines.
    lines = [_powershell_code_only(line) for line in raw]
    code = "\n".join(lines)
    offsets = []
    position = 0
    for line in lines:
        offsets.append(position)
        position += len(line) + 1
    stack: list[int] = []
    blocks: dict[int, int] = {}
    kinds: dict[int, str] = {}
    for index, character in enumerate(code):
        if character == "{":
            kinds[index] = "function" if not stack and not blocks else (
                "try" if re.search(r"(?:^|[;{}\n])\s*try\s*$", code[:index]) else "other"
            )
            stack.append(index)
        elif character == "}":
            if not stack:
                return None
            blocks[stack.pop()] = index
    if stack:
        return None

    def statements(command):
        result = []
        for number, line in enumerate(lines):
            if not _powershell_command_present(line, command):
                continue
            end = number
            while raw[end].rstrip().endswith("`") and end + 1 < len(lines):
                end += 1
            text = " ".join(lines[number:end + 1])
            match = re.fullmatch(r"\s*\$([A-Za-z_]\w*)\s*=\s*" + re.escape(command) + r"\b[^;{}|()]*", text, re.I)
            if match is None:
                return []
            result.append((offsets[number], offsets[end] + len(lines[end]), match.group(1)))
        return result

    def lifetime(acquisition, release):
        begin, end, variable = acquisition
        active_blocks = [opening for opening, closing in blocks.items() if opening < begin < closing]
        if not active_blocks or any(kinds[opening] not in {"function", "try"} for opening in active_blocks):
            return None
        if re.search(r"\b(?:return|exit|break|continue)\b", code[:begin], re.I):
            return None
        following = re.match(r"\s*try\s*\{", code[end:])
        if following is None:
            return None
        opening = end + following.end() - 1
        closing = blocks.get(opening)
        if closing is None:
            return None
        final = re.match(r"\s*finally\s*\{", code[closing + 1:])
        if final is None:
            return None
        final_open = closing + final.end()
        final_close = blocks.get(final_open)
        if final_close is None or not re.fullmatch(
            r"\s*" + re.escape(release) + r"\s+\$" + re.escape(variable) + r"\s*;?\s*",
            code[final_open + 1:final_close], re.I,
        ):
            return None
        if len(re.findall(r"(?<![\w-])" + re.escape(release) + r"(?![\w-])", code, re.I)) != 1:
            return None
        held = code[opening + 1:closing]
        if re.search(r"\$" + re.escape(variable) + r"(?:\.\w+)*\s*=(?!=)", held, re.I):
            return None
        if re.search(r"\$" + re.escape(variable) + r"(?:\.\w+)*\.(?:Dispose|ReleaseMutex)\s*\(", held, re.I):
            return None
        # Inventory sites have line precision: mixed boundary/code lines cannot
        # be proven wholly inside the held body.
        next_line = code.find("\n", opening)
        previous_line = code.rfind("\n", 0, closing)
        if next_line < 0 or code[opening + 1:next_line].strip() or code[previous_line + 1:closing].strip():
            return None
        return opening, closing, final_close

    authority = statements(str(entry_guard["guard_name"]))
    if len(authority) != 1:
        return None
    region = lifetime(authority[0], str(entry_guard["release_name"]))
    if region is None:
        return None
    opening, closing, _ = region
    admission = statements("Enter-ContainerWriterAdmission")
    if _powershell_command_present(code, "Enter-ContainerWriterAdmission"):
        if len(admission) != 1 or admission[0][2].casefold() == authority[0][2].casefold():
            return None
        nested = lifetime(admission[0], "Exit-ContainerWriterAdmission")
        if nested is None or code[opening + 1:admission[0][0]].strip() or nested[2] >= closing:
            return None
        opening, closing, _ = nested
    start = int(function["start"])
    return {"start": start + code[:opening].count("\n") + 1,
            "end": start + code[:closing].count("\n") - 1,
            "guard_line": start + code[:authority[0][0]].count("\n")}


def _powershell_local_guard_at_line(function, entry_guard, line):
    region = _powershell_local_authority_region(function, entry_guard)
    return region if region is not None and region["start"] <= line <= region["end"] else None


def _powershell_function_guard_proofs(
    relative_path: Path,
    lines: list[str],
    function_ranges: list[dict[str, Any]],
    entry_guard: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Prove every direct intra-file caller chain starts inside the lifetime.

    Safe, unsafe, and explicitly non-production roots are propagated separately.
    A function reached from any unsafe top-level call remains unguarded even when
    another caller reaches it after admission.
    """
    functions = {str(row["name"]): row for row in function_ranges}
    call_sites: dict[str, list[dict[str, Any]]] = {
        name: [] for name in functions
    }
    mode_ranges = _powershell_mode_ranges(lines, function_ranges)
    non_production_modes = POWERSHELL_NON_PRODUCTION_FUNCTION_MODES.get(
        relative_path, {}
    )
    local_regions = {name: _powershell_local_authority_region(row, entry_guard)
                     for name, row in functions.items()}
    local_sites: dict[tuple[str, int], int] = {}
    for line_number, line in enumerate(lines, start=1):
        code = _powershell_code_only(line)
        if not code.strip():
            continue
        caller = _powershell_function_at_line(function_ranges, line_number)
        for name, function in functions.items():
            if line_number == int(function["start"]) and re.match(
                rf"^\s*function\s+{re.escape(name)}\b", line, re.IGNORECASE
            ):
                continue
            if not _powershell_command_present(code, name):
                continue
            region = local_regions.get(str(caller["name"])) if caller else None
            if region is not None and region["start"] <= line_number <= region["end"]:
                local_sites[(name, line_number)] = region["guard_line"]
            expected_mode = str(non_production_modes.get(name, "")).casefold()
            actual_mode = next(
                (
                    str(row["mode"])
                    for row in mode_ranges
                    if int(row["start"]) <= line_number <= int(row["end"])
                ),
                "",
            )
            call_sites[name].append(
                {
                    "caller": (
                        "__script__" if caller is None else str(caller["name"])
                    ),
                    "line": line_number,
                    "guarded_top_level": bool(
                        caller is None
                        and (
                            _powershell_line_in_guard_lifetime(
                                entry_guard, line_number
                            )
                            or (
                                name == entry_guard.get("guard_name")
                                and line_number == entry_guard.get("guard_line")
                            )
                        )
                    ),
                    "non_production_mode": (
                        actual_mode
                        if caller is None
                        and expected_mode
                        and actual_mode == expected_mode
                        else ""
                    ),
                }
            )

    safe_reachable: set[str] = set()
    unsafe_reachable: set[str] = set()
    non_production_reachable: set[str] = set()
    safe_origins: dict[str, set[int]] = defaultdict(set)
    for name, sites in call_sites.items():
        for site in sites:
            if site["caller"] != "__script__":
                continue
            if site["non_production_mode"]:
                non_production_reachable.add(name)
            elif site["guarded_top_level"]:
                safe_reachable.add(name)
                safe_origins[name].add(int(entry_guard["guard_line"]))
            else:
                unsafe_reachable.add(name)

    changed = True
    while changed:
        changed = False
        for name, sites in call_sites.items():
            for site in sites:
                caller = str(site["caller"])
                if caller == "__script__":
                    continue
                local = local_sites.get((name, int(site["line"])))
                if caller in safe_reachable or (local is not None and caller in unsafe_reachable):
                    origins = {local} if local is not None else safe_origins[caller]
                    if name not in safe_reachable or not origins <= safe_origins[name]:
                        safe_reachable.add(name)
                        safe_origins[name].update(origins)
                        changed = True
                if local is None and caller in unsafe_reachable and name not in unsafe_reachable:
                    unsafe_reachable.add(name)
                    changed = True
                if caller in non_production_reachable and name not in non_production_reachable:
                    non_production_reachable.add(name)
                    changed = True

    proofs: dict[str, dict[str, Any]] = {}
    for name in sorted(functions):
        production_reachable = name in safe_reachable or name in unsafe_reachable
        guarded = bool(name in safe_reachable and name not in unsafe_reachable)
        non_production_only = bool(
            name in non_production_reachable and not production_reachable
        )
        proofs[name] = {
            "function": name,
            "call_sites": call_sites[name],
            "production_reachable": production_reachable,
            "safe_reachable": name in safe_reachable,
            "unsafe_reachable": name in unsafe_reachable,
            "non_production_reachable": name in non_production_reachable,
            "non_production_only": non_production_only,
            "guarded": guarded or non_production_only,
            "guard_name": (
                str(entry_guard.get("guard_name", ""))
                if guarded
                else ("non_production_mode" if non_production_only else "")
            ),
            "guard_line": (
                min(safe_origins[name])
                if guarded
                else (
                    min(
                        int(site["line"])
                        for site in call_sites[name]
                        if site["non_production_mode"]
                    )
                    if non_production_only
                    else None
                )
            ),
        }
    return proofs


def _powershell_bootstrap_caller_proofs(
    root: Path, paths: tuple[Path, ...]
) -> dict[str, dict[str, Any]]:
    """Admit shared execution only when every shipped caller is fenced.

    The bootstrap library is byte pinned by the registered installers and the
    public writer-session adapter. A shared
    function has no script admission of its own, so its direct caller closure
    must terminate entirely in their proven admission lifetimes.
    Ambiguous names, unreachable callers and any early/late call fail closed.
    """
    library = Path("tools/bootstrap_integrity.ps1")
    modules = {}
    definitions: dict[str, list[Path]] = defaultdict(list)
    for path in paths:
        lines = (root / path).read_text(encoding="utf-8").splitlines()
        ranges = _powershell_function_ranges(lines)
        entry = _powershell_entry_guard(path, lines, ranges)
        proofs = _powershell_function_guard_proofs(path, lines, ranges, entry)
        modules[path] = (lines, ranges, entry, proofs)
        for row in ranges:
            definitions[str(row["name"])].append(path)
    if library not in modules:
        return {}
    names = {
        str(row["name"])
        for row in modules[library][1]
        if definitions[str(row["name"])] == [library]
    }
    callers: dict[str, list[dict[str, Any]]] = {name: [] for name in names}
    for path, (lines, ranges, entry, proofs) in modules.items():
        for number, line in enumerate(lines, 1):
            code = _powershell_code_only(line)
            folded = code.casefold()
            owner = _powershell_function_at_line(ranges, number)
            for name in names:
                if name.casefold() not in folded:
                    continue
                if re.match(rf"^\s*function\s+{re.escape(name)}\b", code, re.I):
                    continue
                if not _powershell_command_present(code, name):
                    continue
                caller = "__script__" if owner is None else str(owner["name"])
                admitted_installer = path in {
                    Path("INSTALL_CANONICAL_PORTABLE.ps1"), Path("INSTALL_THIS_PC.ps1"),
                    Path("tools/container_writer_session.ps1"),
                }
                safe = admitted_installer and bool(entry["valid"]) and (
                    _powershell_line_in_guard_lifetime(entry, number)
                    if owner is None else bool(proofs[caller]["guarded"] or
                        _powershell_local_guard_at_line(owner, entry, number))
                )
                callers[name].append({"file": path.as_posix(), "caller": caller,
                                      "line": number, "installer_guarded": safe})
    admitted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, sites in callers.items():
            if name in admitted or not sites:
                continue
            if all(site["installer_guarded"] or (
                site["file"] == library.as_posix() and site["caller"] in admitted
            ) for site in sites):
                admitted.add(name)
                changed = True
    return {
        name: {"function": name, "call_sites": callers[name],
               "guarded": True, "guard_name": "byte_pinned_installer_caller_closure",
               "guard_line": min(site["line"] for site in callers[name])}
        for name in sorted(admitted)
    }


def _powershell_target(fragment: str) -> tuple[str, bool]:
    target = fragment.strip().rstrip(";|")
    static = bool(target) and not target.startswith(("$", "(", "@{"))
    return target, static


def _powershell_module_prologue_lines(source: bytes) -> frozenset[int]:
    """Only the byte-exact OS block at the script's first command is exempt."""
    if source.count(PS_MODULE_PROLOGUE) != 1:
        return frozenset()
    before, after = source.split(PS_MODULE_PROLOGUE)
    if before and not before.endswith(b"\n") and before != b"\xef\xbb\xbf":
        return frozenset()
    prefix = "\n".join(_powershell_code_only(line) for line in
                       before.decode("utf-8-sig").splitlines()).strip()
    if prefix:
        parameter = re.match(r"(?i)(?:\[CmdletBinding\(\)\]\s*)?param\s*\(", prefix)
        if parameter is None:
            return frozenset()
        depth = 1
        for index, character in enumerate(prefix[parameter.end():], parameter.end()):
            depth += (character == "(") - (character == ")")
            if depth == 0:
                if prefix[index + 1:].strip():
                    return frozenset()
                break
        # Parameter binding happens before the script body. Even an OS cmdlet
        # in a default or ValidateScript must not precede the accepted imports.
        if depth or re.search(r"\b[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*\b|[&|]", prefix):
            return frozenset()
    suffix = "\n".join(_powershell_code_only(line) for line in
                       after.decode("utf-8").splitlines()).lstrip()
    if re.match(r"(?i)(?:\[CmdletBinding\(\)\]\s*)?param\s*\(", suffix):
        return frozenset()
    first = before.count(b"\n") + 1
    return frozenset((first, first + 1))


def _powershell_line_sites(
    lines: list[str], index: int
) -> list[dict[str, Any]]:
    line = lines[index - 1]
    code = _powershell_code_only(line)
    if not code.strip():
        return []
    context_start = max(0, index - 3)
    context_end = min(len(lines), index + 2)
    context = "\n".join(lines[context_start:context_end])
    context_folded = context.casefold()
    sites: list[dict[str, Any]] = []

    def add(kind: str, command: str, target: str = "", static: bool = True) -> None:
        row = {
            "kind": kind,
            "command": command,
            "target": target,
            "target_static": static,
        }
        if row not in sites:
            sites.append(row)

    dot_source = re.search(r"(?<![A-Za-z0-9_.])\.\s+([^;|}]+)", code)
    if dot_source is not None:
        target, static = _powershell_target(dot_source.group(1))
        add("dot_source", ".", target, static)
    module_import = _powershell_statement_command(
        code,
        r"Import-Module|Import-PSSession|using\s+module",
    )
    if module_import is not None:
        add("dot_source", module_import.group(1), "", False)

    start_process = next(
        (match for match in re.finditer(r"(?i)(?<![A-Za-z0-9_-])Start-Process\b", code)
         if not _powershell_assignment_key(code, match.start(), match.end())),
        None,
    )
    if start_process is not None:
        arguments = code[start_process.end():]
        file_path = re.search(r"(?i)-FilePath\s+([^\s,;|]+)", arguments)
        positional = re.search(r"^\s*([^\s,;|]+)", arguments)
        target, static = _powershell_target(
            (file_path or positional).group(1) if (file_path or positional) else ""
        )
        add("start_process", "Start-Process", target, static)
    start_alias = _powershell_statement_command(
        code,
        r"saps|start|Invoke-Item|ii",
    )
    if start_alias is not None:
        add("start_process", start_alias.group(1), "", False)

    invoke_expression = next(
        (
            command
            for command in ("Invoke-Expression", "IEX")
            if _powershell_command_present(code, command)
        ),
        "",
    )
    if invoke_expression:
        add("invoke_expression", invoke_expression, "", False)

    call_operator = re.search(
        r"(?<![A-Za-z0-9_>])&\s*([^\s|;,)]+)",
        code,
    )
    if call_operator is not None:
        target, static = _powershell_target(call_operator.group(1))
        add("call_operator", "&", target, static)

    direct_names = "|".join(
        re.escape(command) for command in POWERSHELL_DIRECT_COMMAND_NAMES
    )
    native_command = _powershell_statement_command(
        code,
        rf"(?:\.?\.?[\\/])?[A-Za-z][A-Za-z0-9_.\\:/-]*\.(?:exe|com|cmd|bat|ps1|psm1)|{direct_names}",
    )
    if native_command is not None:
        target = native_command.group(1)
        add("native_command", target, target, True)

    if (
        "win32_process" in context_folded
        and "create" in context_folded
        and (
            _powershell_command_present(code, "Invoke-CimMethod")
            or _powershell_command_present(code, "Invoke-WmiMethod")
            or "[wmiclass]" in context_folded
        )
    ):
        add("com_wmi_process_create", "Win32_Process.Create", "", False)
    if (
        "-comobject" in line.casefold()
        or "gettypefromprogid" in line.casefold()
        or "wscript.shell" in line.casefold()
        or "shell.application" in line.casefold()
    ):
        add("com_wmi_process_create", "COM process launch", "", False)

    native_process_api = next(
        (
            api
            for api in POWERSHELL_NATIVE_PROCESS_APIS
            if re.search(
                rf"(?i)(?<![A-Za-z0-9_-]){re.escape(api)}(?:A|W)?(?![A-Za-z0-9_-])",
                code,
            )
        ),
        "",
    )
    if native_process_api:
        add("native_process_api", native_process_api, "", False)
    if re.search(r"(?i)\[ContainerAuditCanonicalUserProcess\]\s*::\s*StartLimited(?:WithOverrides)?\s*\(", code):
        add("native_process_api", "ContainerAuditCanonicalUserProcess.StartLimited", "", False)

    if re.search(
        r"(?i)(?:System\.)?Diagnostics\.Process\s*\]\s*::\s*Start\b|"
        r"\[\s*Diagnostics\.Process\s*\]\s*::\s*Start\b",
        code,
    ) or re.search(
        r"(?i)\[(?:System\.)?Diagnostics\.Process\]\s*::\s*new\b|"
        r"New-Object\s+(?:System\.)?Diagnostics\.Process\b",
        code,
    ) or ("processstartinfo" in context_folded and re.search(r"(?i)\.Start\s*\(", code)) or re.search(
        r"(?i)\[KMTechInstallationChildCapture\]\s*::\s*Run\s*\(", code
    ):
        add("dotnet_process_start", "System.Diagnostics.Process.Start", "", False)

    if "schedule.service" in line.casefold() or (
        "schedule.service" in "\n".join(lines).casefold()
        and re.search(
            r"(?i)\.(?:RegisterTaskDefinition|RegisterTask|DeleteTask|NewTask)\s*\(",
            code,
        )
    ):
        add("scheduler_com", "Schedule.Service", "", False)

    service_command = next(
        (
            command
            for command in SERVICE_MUTATION_COMMANDS
            if _powershell_command_present(code, command)
        ),
        "",
    )
    service_api = bool(
        service_command
        or re.search(r"(?i)(?<![A-Za-z0-9_.-])sc\.exe(?![A-Za-z0-9_.-])", code)
        or (
            "win32_service" in context_folded
            and any(
                name in context_folded
                for name in (
                    "create",
                    "changestartmode",
                    "delete",
                    "startservice",
                    "stopservice",
                )
            )
        )
        or "serviceprocess.servicecontroller" in context_folded
        or re.search(
            r"(?i)\b(?:OpenSCManagerW?|CreateServiceW?|ChangeServiceConfigW?|DeleteService)\b",
            context,
        )
    )
    if service_api:
        add("service_control_api", service_command or "service control API", "", False)

    reflective_boundary = bool(
        (
            any(
                marker.casefold() in code.casefold()
                for marker in POWERSHELL_REFLECTION_COMMANDS
            )
            and (
                re.search(r"(?i)\.(?:Invoke|InvokeMember)\s*\(", code)
                or "getmethod" in code.casefold()
            )
        )
        or re.search(r"(?i)\.Invoke(?:ReturnAsIs)?\s*\(", code)
        or re.search(r"(?i)\[ScriptBlock\]\s*::\s*Create\s*\(", code)
        or re.search(r"(?i)\.InvokeScript\s*\(", code)
        or re.search(r"(?i)\.(?:AddScript|BeginInvoke)\s*\(", code)
        or re.search(
            r"(?i)\b(?:RunspaceFactory|CreateRunspace|CreatePipeline)\b",
            code,
        )
        or any(
            _powershell_command_present(code, command)
            for command in (
                "Add-Type",
                "Invoke-Command",
                "New-Module",
                "Register-EngineEvent",
                "Register-ObjectEvent",
                "Register-WmiEvent",
                "Start-Job",
                "Start-ThreadJob",
            )
        )
        or bool(re.search(r"(?i)ForEach-Object\b.*\s-Parallel\b", code))
    )
    if reflective_boundary:
        add("reflective_invocation", "reflection invoke", "", False)

    scheduled_command = next(
        (
            command
            for command in SCHEDULED_TASK_MUTATION_COMMANDS
            if _powershell_command_present(code, command)
        ),
        "",
    )
    if scheduled_command:
        add("scheduled_task_cmdlet", scheduled_command)
    if service_command:
        add("service_cmdlet", service_command)

    filesystem_commands = [
        command
        for command in POWERSHELL_FILESYSTEM_MUTATION_COMMANDS
        if _powershell_command_present(code, command)
    ]
    dotnet_file = re.search(
        r"(?i)\[(?:System\.)?(?:IO\.)?File\]\s*::\s*"
        r"(?:AppendAllText|Copy|Delete|Move|Replace|WriteAllBytes|WriteAllLines|WriteAllText)\b",
        code,
    )
    native_acl = bool(
        call_operator is not None
        and re.search(r"(?i)(?:\$icacls\b|\bicacls(?:\.exe)?\b)", line)
    )
    if filesystem_commands or dotnet_file or native_acl:
        command = ",".join(filesystem_commands)
        if dotnet_file:
            command = command or ".NET File mutation"
        if native_acl:
            command = command or "icacls.exe"
        add("filesystem_mutation", command)

    registry_commands = [
        command
        for command in POWERSHELL_REGISTRY_MUTATION_COMMANDS
        if _powershell_command_present(code, command)
    ]
    if registry_commands:
        add("registry_mutation", ",".join(registry_commands))

    return sites


def _powershell_site_guard(
    relative_path: Path,
    site: dict[str, Any],
    function: dict[str, Any] | None,
    entry_guard: dict[str, Any],
    function_guards: dict[str, dict[str, Any]],
    *,
    module_prologue_lines: frozenset[int] = frozenset(),
) -> tuple[bool, str, int | None]:
    function_name = "" if function is None else str(function["name"])
    if site["kind"] == "dot_source" and site["command"].casefold() in {
        "import-module", "import-pssession", "using module",
    }:
        if site["command"] == "Import-Module" and int(site["line"]) in module_prologue_lines:
            return True, "byte_exact_os_module_prologue", int(site["line"])
        return False, "", None
    if site["kind"] == "scheduled_task_cmdlet":
        approved_wrapper = (
            relative_path == Path("tools/container_writer_fence.ps1")
            and function_name in APPROVED_SCHEDULED_TASK_WRAPPERS
            and any(
                COMMON_FENCE_GUARD_PREFIX in candidate
                for candidate in ([] if function is None else function["lines"])
            )
        )
        if approved_wrapper:
            return True, COMMON_FENCE_GUARD_PREFIX, int(function["start"])
    if site["kind"] == "call_operator" and (
        relative_path == Path("tools/container_writer_fence.ps1")
        and function_name == COMMON_FENCE_GUARD_PREFIX
    ):
        return True, COMMON_FENCE_GUARD_PREFIX, int(function["start"])
    if site["kind"] == "dot_source":
        approved = POWERSHELL_APPROVED_DOT_SOURCE_SYMBOLS.get(
            relative_path, frozenset()
        )
        if site["target"] in approved:
            return True, "byte_pinned_function_library", int(site["line"])
    proof = function_guards.get(function_name, {})
    if (relative_path == Path("tools/bootstrap_integrity.ps1")
        and proof.get("guarded")
        and proof.get("guard_name") == "byte_pinned_installer_caller_closure"):
        return True, str(proof["guard_name"]), int(proof["guard_line"])
    if entry_guard["valid"]:
        if function is not None:
            local = _powershell_local_guard_at_line(function, entry_guard, int(site["line"]))
            if local is not None:
                return True, str(entry_guard["guard_name"]), local["guard_line"]
        if function is None and _powershell_line_in_guard_lifetime(
            entry_guard, int(site["line"])
        ):
            return (
                True,
                str(entry_guard["guard_name"]),
                int(entry_guard["guard_line"]),
            )
        if function is not None:
            proof = function_guards.get(function_name, {})
            if proof.get("guarded"):
                return (
                    True,
                    str(proof["guard_name"]),
                    int(proof["guard_line"]),
                )
    return False, "", None


def _collect_powershell_inventory(root: Path) -> dict[str, Any]:
    powershell_paths = _discover_shipped_powershell_paths(root)
    bootstrap_callers = _powershell_bootstrap_caller_proofs(root, powershell_paths)
    files: list[dict[str, Any]] = []
    all_sites: list[dict[str, Any]] = []
    execution_sites: list[dict[str, Any]] = []
    direct_mutation_sites: list[dict[str, Any]] = []
    script_entrypoints: list[dict[str, Any]] = []
    function_guard_rows: list[dict[str, Any]] = []
    mutation_scopes: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    delegated_sources: list[str] = []
    for relative_path in powershell_paths:
        source_bytes = (root / relative_path).read_bytes()
        lines = source_bytes.decode("utf-8-sig").splitlines()
        module_prologue_lines = _powershell_module_prologue_lines(source_bytes)
        function_ranges = _powershell_function_ranges(lines)
        atomic_helpers = [row for row in function_ranges if row["name"] in POWERSHELL_ATOMIC_FUNCTIONS]
        if atomic_helpers:
            helper_bytes = "\n\n".join("\n".join(row["lines"]) for row in atomic_helpers).encode("utf-8")
            if (relative_path != Path("tools/bootstrap_integrity.ps1")
                    or {row["name"] for row in atomic_helpers} != POWERSHELL_ATOMIC_FUNCTIONS
                    or hashlib.sha256(helper_bytes).hexdigest() != POWERSHELL_ATOMIC_HELPERS_SHA256):
                raise InventoryError("PowerShell atomic replacement facade body changed")
        entry_guard = _powershell_entry_guard(relative_path, lines, function_ranges)
        function_guards = _powershell_function_guard_proofs(
            relative_path,
            lines,
            function_ranges,
            entry_guard,
        )
        if relative_path == Path("tools/bootstrap_integrity.ps1"):
            for name, proof in bootstrap_callers.items():
                function_guards[name] = {**function_guards[name], **proof}
        if relative_path.name == "INSTALL_CANONICAL_PORTABLE.ps1":
            delegated_sources = _extract_ps_delegated_sources(lines)
        per_file_sites: list[dict[str, Any]] = []
        for index in range(1, len(lines) + 1):
            function = _powershell_function_at_line(function_ranges, index)
            function_name = "" if function is None else str(function["name"])
            if function_name in POWERSHELL_ATOMIC_FUNCTIONS:
                # Exact leaf effects are inventoried as mutations at every facade caller.
                continue
            if _powershell_command_present(_powershell_code_only(lines[index-1]), "Invoke-ContainerAtomicReplaceOnce"):
                raise InventoryError("PowerShell atomic private backend escaped its facade")
            for discovered in _powershell_line_sites(lines, index):
                site = {
                    "file": _relative(relative_path),
                    "line": index,
                    "function": function_name,
                    **discovered,
                }
                guarded, guard_name, guard_line = _powershell_site_guard(
                    relative_path,
                    site,
                    function,
                    entry_guard,
                    function_guards,
                    module_prologue_lines=module_prologue_lines,
                )
                site.update(
                    {
                        "guarded": guarded,
                        "guard_name": guard_name,
                        "guard_line": guard_line,
                    }
                )
                per_file_sites.append(site)
                all_sites.append(site)
                if site["kind"] in {
                    "call_operator",
                    "com_wmi_process_create",
                    "dot_source",
                    "dotnet_process_start",
                    "invoke_expression",
                    "native_command",
                    "native_process_api",
                    "reflective_invocation",
                    "scheduler_com",
                    "service_control_api",
                    "start_process",
                }:
                    execution_sites.append(site)
                if site["kind"] in {
                    "filesystem_mutation",
                    "registry_mutation",
                    "scheduled_task_cmdlet",
                    "service_cmdlet",
                }:
                    direct_mutation_sites.append(site)
                if site["kind"] != "dot_source":
                    mutation_scopes[(_relative(relative_path), function_name)].append(site)
        writer_sites = [
            site
            for site in per_file_sites
            if site["kind"] not in {"dot_source"}
        ]
        if writer_sites and relative_path not in POWERSHELL_LIBRARY_PATHS:
            registered = relative_path in POWERSHELL_ENTRYPOINT_GUARDS
            script_entrypoints.append(
                {
                    "file": _relative(relative_path),
                    "writer_source": (
                        str(entry_guard["writer_source"]) if registered else ""
                    ),
                    "guard_name": (
                        str(entry_guard["guard_name"])
                        if registered
                        else "registered_shipped_powershell_guard"
                    ),
                    "guard_kind": (
                        str(entry_guard["guard_kind"])
                        if registered
                        else "unregistered_shipped_asset"
                    ),
                    "guard_line": entry_guard["guard_line"] if registered else None,
                    "release_name": (
                        str(entry_guard["release_name"]) if registered else ""
                    ),
                    "release_line": (
                        entry_guard["release_line"] if registered else None
                    ),
                    "guarded": bool(entry_guard["valid"]) if registered else False,
                    "writer_site_count": len(writer_sites),
                    "writer_site_kinds": sorted(
                        {str(site["kind"]) for site in writer_sites}
                    ),
                }
            )
        function_guard_rows.extend(
            {"file": _relative(relative_path), **function_guards[name]}
            for name in sorted(
                {
                    str(site["function"])
                    for site in per_file_sites
                    if site["function"]
                }
            )
        )
        files.append(
            {
                "file": _relative(relative_path),
                "entry_guard": entry_guard,
                "sites": per_file_sites,
            }
        )
    files.sort(key=lambda row: row["file"])
    all_sites.sort(key=lambda row: (row["file"], row["line"], row["kind"]))
    execution_sites.sort(
        key=lambda row: (row["file"], row["line"], row["kind"])
    )
    direct_mutation_sites.sort(
        key=lambda row: (row["file"], row["line"], row["kind"])
    )
    script_entrypoints.sort(key=lambda row: row["file"])
    scheduled_sites = [
        {
            "file": site["file"],
            "line": site["line"],
            "command": site["command"],
            "wrapper_function": site["function"],
            "guard_name": site["guard_name"],
            "guard_line": site["guard_line"],
            "register_line": None,
            "guarded": site["guarded"],
            "registered": site["guarded"],
        }
        for site in all_sites
        if site["kind"] == "scheduled_task_cmdlet"
    ]
    scope_rows = [
        {
            "file": file,
            "function": function or "__script__",
            "site_count": len(sites),
            "site_kinds": sorted({str(site["kind"]) for site in sites}),
            "guarded": all(bool(site["guarded"]) for site in sites),
        }
        for (file, function), sites in sorted(mutation_scopes.items())
    ]
    guarded_failure_kinds = {
        "call_operator",
        "com_wmi_process_create",
        "dot_source",
        "dotnet_process_start",
        "invoke_expression",
        "native_command",
        "native_process_api",
        "reflective_invocation",
        "scheduled_task_cmdlet",
        "scheduler_com",
        "service_cmdlet",
        "service_control_api",
        "start_process",
    }
    direct_entrypoint_guard_kinds = {
        "filesystem_mutation",
        "registry_mutation",
    }
    guard_failures = [
        site
        for site in all_sites
        if (
            site["kind"] in guarded_failure_kinds
            or (
                site["kind"] in direct_entrypoint_guard_kinds
                and Path(str(site["file"])) in POWERSHELL_ENTRYPOINT_GUARDS
            )
        )
        and not site["guarded"]
    ]
    guard_failures.extend(
        {
            **site,
            "kind": "library_top_level_writer",
            "command": site["command"] or site["kind"],
        }
        for site in all_sites
        if Path(str(site["file"])) in POWERSHELL_LIBRARY_PATHS
        and not site["function"]
        and site["kind"] != "dot_source"
    )
    guard_failures.extend(
        {
            "file": entry["file"],
            "line": 1,
            "function": "__script__",
            "kind": "script_entrypoint",
            "command": entry["file"],
            "target": entry["file"],
            "target_static": True,
            "guarded": False,
            "guard_name": entry["guard_name"],
            "guard_line": entry["guard_line"],
        }
        for entry in script_entrypoints
        if not entry["guarded"]
    )
    guard_failures.sort(
        key=lambda row: (str(row["file"]), int(row["line"]), str(row["kind"]))
    )
    writer_sinks = [
        {
            "file": entry["file"],
            "source": entry["writer_source"],
            "guard_name": entry["guard_name"],
            "guard_line": entry["guard_line"],
            "release_name": entry["release_name"],
            "release_line": entry["release_line"],
            "guarded": entry["guarded"],
            "writer_site_count": entry["writer_site_count"],
            "writer_site_kinds": entry["writer_site_kinds"],
        }
        for entry in script_entrypoints
        if entry["writer_source"]
    ]
    return {
        "common_guard_prefix": COMMON_FENCE_GUARD_PREFIX,
        "asset_derivation": "portable_builder.PORTABLE_INSTALL_ASSETS",
        "asset_paths": [_relative(path) for path in powershell_paths],
        "files": files,
        "function_guard_proofs": function_guard_rows,
        "mutation_sites": scheduled_sites,
        "all_sites": all_sites,
        "execution_sites": execution_sites,
        "direct_mutation_sites": direct_mutation_sites,
        "mutation_scopes": scope_rows,
        "script_entrypoints": script_entrypoints,
        "writer_sinks": writer_sinks,
        "guard_failures": guard_failures,
        "site_counts_by_kind": {
            kind: sum(1 for site in all_sites if site["kind"] == kind)
            for kind in sorted({str(site["kind"]) for site in all_sites})
        },
        "installer_delegated_sources": delegated_sources,
    }


def _shell_kit_delegated_fence(
    root: Path, parsed_modules: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """Trust only the exact kit and an app entry that installs the real CA admission."""
    shell_root = root / SCREEN_SHELL_DIR
    if not shell_root.is_dir():
        return None
    paths = {path.relative_to(root).as_posix() for path in shell_root.rglob("*.py")}
    ready_path = shell_root / "SHELL-READY-v3.16.json"
    if (
        paths != set(SHELL_KIT_PYTHON_SHA256)
        or any(hashlib.sha256((root / path).read_bytes()).hexdigest() != sha
               for path, sha in SHELL_KIT_PYTHON_SHA256.items())
        or not ready_path.is_file()
        or hashlib.sha256(ready_path.read_bytes()).hexdigest() != SHELL_KIT_READY_SHA256
    ):
        raise InventoryError("screen shell kit must match the pinned SHELL-READY v3.16.3.1")
    tree = parsed_modules[SHELL_KIT_WRITE_MODULE]["tree"]
    sites = next((ast.literal_eval(node.value) for node in tree.body
                  if isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id == "SHELL_WRITE_SITES"), None)
    if sites != SHELL_KIT_WRITE_SITES:
        raise InventoryError("screen shell write sites differ from the pinned kit")
    app = parsed_modules.get("ca_screen_bridge", {}).get("tree")
    functions = {node.name: node for node in app.body if isinstance(node, ast.FunctionDef)} if app else {}
    guard = functions.get("admission_write_guard")
    body = list(guard.body) if guard else []
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    returned = body[0].value if len(body) == 1 and isinstance(body[0], ast.Return) else None
    imports_admission = bool(app) and any(
        isinstance(node, ast.ImportFrom) and node.module == "writer_session_fence"
        and any(alias.name == "writer_admission" and alias.asname is None for alias in node.names)
        for node in app.body
    )
    real_guard = (
        imports_admission and guard is not None and not guard.decorator_list
        and [arg.arg for arg in guard.args.args] == ["op", "path", "kind"]
        and isinstance(returned, ast.Call) and isinstance(returned.func, ast.Name)
        and returned.func.id == "writer_admission" and not returned.keywords
        and len(returned.args) == 1 and _string_literal(returned.args[0]) == SHELL_KIT_WRITER_SOURCE
    )
    runner = functions.get("screen_runner")
    installs_guard = runner is not None and any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "run_app"
        and any(keyword.arg == "write_guard" and isinstance(keyword.value, ast.Name)
                and keyword.value.id == "admission_write_guard" for keyword in node.keywords)
        for node in ast.walk(runner)
    )
    installs_marker_guard = runner is not None and any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "allowed"
        and any(keyword.arg == "write_guard" and isinstance(keyword.value, ast.Name)
                and keyword.value.id == "admission_write_guard" for keyword in node.keywords)
        for node in ast.walk(runner)
    )
    if not real_guard or not installs_guard or not installs_marker_guard:
        raise InventoryError("CA screen entry must install the existing writer admission as the shell write guard")
    return {
        "ready_version": SHELL_KIT_READY_VERSION,
        "ready_sha256": SHELL_KIT_READY_SHA256,
        "python_files": [{"path": path, "sha256": sha} for path, sha in sorted(SHELL_KIT_PYTHON_SHA256.items())],
        "write_module": SHELL_KIT_WRITE_MODULE,
        "write_sites": sorted(SHELL_KIT_WRITE_SITES),
        "writer_source": SHELL_KIT_WRITER_SOURCE,
        "reason": (
            "Container_Audit --new-screen installs ca_screen_bridge.admission_write_guard through run_app; "
            "each shell_fileio write acquires and releases the existing CA writer_admission; "
            "shell/host.py standalone kit mode has no product shortcut or installer route"
        ),
    }


def derive_inventory(root: Path | None = None) -> dict[str, Any]:
    repo_root = (root or ROOT).resolve()
    module_index = _build_module_index(repo_root)
    shipped_application_paths = _discover_shipped_application_paths(repo_root)
    entrypoint_modules = tuple(_module_name(path) for path in shipped_application_paths)
    parsed_modules, import_graph = _collect_import_closure(
        root=repo_root,
        entrypoint_modules=entrypoint_modules,
        module_index=module_index,
    )
    analysis_modules = dict(parsed_modules)
    unused_module = "kmtech_shared.diagnostic_log"
    pinned_unused_sources = []
    if unused_module in parsed_modules:
        unused = parsed_modules[unused_module]
        unused_sha = hashlib.sha256((repo_root / unused["path"]).read_bytes()).hexdigest()
        importers = set()
        for name, payload in parsed_modules.items():
            if name == unused_module:
                continue
            if unused_module in import_graph[name]:
                importers.add(name)
            for node in ast.walk(payload["tree"]):
                if isinstance(node, ast.Import) and any(
                    alias.name == "kmtech_shared" or alias.name.startswith(unused_module)
                    for alias in node.names
                ):
                    importers.add(name)
                if isinstance(node, ast.ImportFrom) and node.module == "kmtech_shared" and any(
                    alias.name in {"diagnostic_log", "*"} for alias in node.names
                ):
                    importers.add(name)
                if isinstance(node, ast.Call) and any(
                    isinstance(value, ast.Constant) and isinstance(value.value, str)
                    and value.value.replace("\\", "/") in {
                        "kmtech_shared", unused_module, ".diagnostic_log", "diagnostic_log",
                        "kmtech_shared/diagnostic_log.py",
                    }
                    for value in [*node.args, *(keyword.value for keyword in node.keywords)]
                ):
                    importers.add(name)
        if unused_sha != SHARED_UNUSED_DIAGNOSTIC_SHA256 or importers:
            raise InventoryError("shared diagnostic_log must remain byte-pinned and unconsumed in CA")
        del analysis_modules[unused_module]
        pinned_unused_sources.append({"path": _relative(unused["path"]), "sha256": unused_sha})
    shell_kit_fence = _shell_kit_delegated_fence(repo_root, analysis_modules)
    node_analysis, call_graph, sink_sources, sink_marker_kinds = _analyze_closure(
        parsed_modules=analysis_modules,
        import_graph=import_graph,
        shell_kit_delegated=shell_kit_fence is not None,
    )
    start_nodes = _normalize_start_names(call_graph)
    coverage, predecessor = _coverage_states(
        starts=start_nodes,
        call_graph=call_graph,
        sink_nodes=set(sink_sources),
    )
    sink_rows = _sink_rows(
        parsed_modules=analysis_modules,
        node_analysis=node_analysis,
        sink_sources=sink_sources,
        sink_marker_kinds=sink_marker_kinds,
    )
    mutation_rows = _closure_mutation_rows(
        parsed_modules=analysis_modules,
        node_analysis=node_analysis,
        coverage=coverage,
        predecessor=predecessor,
        sink_sources=sink_sources,
        call_graph=call_graph,
    )
    uncovered = [
        row for row in mutation_rows if row["coverage_status"] == "uncovered"
    ]
    caller_fence_failures = _caller_fence_reference_failures(analysis_modules)
    python_external_control = _collect_python_external_control_commands(analysis_modules)
    external_process_site_count = sum(
        1
        for row in mutation_rows
        for site in row["mutation_sites"]
        if site["category"] == "external_process"
    )

    powershell = _collect_powershell_inventory(repo_root)
    guard_failures = list(powershell["guard_failures"])

    all_sources = sorted(
        {row["source"] for row in sink_rows}
        | {row["source"] for row in powershell["writer_sinks"]}
    )
    route_rows: list[dict[str, Any]] = []
    for route_def in KNOWN_ROUTE_DEFS:
        if route_def["kind"] == "python":
            start_present = route_def["start"] in call_graph
            reachable = _reachable_sources(
                route_def["start"],
                call_graph=call_graph,
                sink_sources=sink_sources,
            )
            reachable_mutators = sorted(
                row["node"]
                for row in mutation_rows
                if route_def["start"] in row["reachable_entrypoints"]
            )
            unsunk_mutators = sorted(
                row["node"]
                for row in mutation_rows
                if route_def["start"] in row["unsunk_entrypoints"]
            )
            route_rows.append(
                {
                    "route_id": route_def["route_id"],
                    "kind": "python",
                    "start": route_def["start"],
                    "start_present": start_present,
                    "reachable_sources": reachable,
                    "reachable_direct_mutation_functions": reachable_mutators,
                    "unfenced_direct_mutation_functions": unsunk_mutators,
                    "pass": start_present and not unsunk_mutators,
                }
            )
            continue
        delegated_raw = list(powershell["installer_delegated_sources"])
        delegated = (
            all_sources
            if delegated_raw == [INVENTORY_ALL_SOURCES_SENTINEL]
            else delegated_raw
        )
        unknown = sorted(set(delegated) - set(all_sources))
        installer_guard_failures = [
            site
            for site in guard_failures
            if site["file"] == route_def["file"]
        ]
        route_rows.append(
            {
                "route_id": route_def["route_id"],
                "kind": "delegated_sources",
                "file": route_def["file"],
                "reachable_sources": delegated,
                "delegation_source": (
                    "code_derived_writer_inventory"
                    if delegated_raw == [INVENTORY_ALL_SOURCES_SENTINEL]
                    else "literal_list"
                ),
                "unknown_delegated_sources": unknown,
                "scheduled_task_guard_failures": installer_guard_failures,
                "pass": not unknown and not installer_guard_failures,
            }
        )
    route_rows.sort(key=lambda row: row["route_id"])

    payload: dict[str, Any] = {
        "schema_version": "container-audit-writer-sink-inventory-v8",
        "entrypoint_modules": [_relative(path) for path in shipped_application_paths],
        "entrypoint_derivation": (
            "all root Python files, all Python files under the portable builder's "
            "shipped package directories, portable/main.py, frozen/update-archive tool "
            "entrypoints parsed from their shipping contracts, the pinned new-screen shell companion, "
            "and their local import closure"
        ),
        "product_entrypoints": start_nodes,
        "closure_modules": [
            _relative(parsed_modules[module_name]["path"])
            for module_name in sorted(parsed_modules)
        ],
        "import_closure_edges": {
            module_name: import_graph.get(module_name, [])
            for module_name in sorted(parsed_modules)
        },
        "writer_sink_sources": all_sources,
        "writer_sinks": sink_rows,
        "directory_preparation_forwarding": node_analysis.get(
            DIRECTORY_PREPARATION_HELPER, {}
        ).get("directory_preparation_forwarding", []),
        "atomic_replacement_forwarding": node_analysis.get(
            ATOMIC_REPLACEMENT_HELPER, {}
        ).get("atomic_replacement_forwarding", []),
        "closure_direct_mutation_functions": mutation_rows,
        "uncovered_direct_mutation_functions": uncovered,
        "caller_fence_reference_failures": caller_fence_failures,
        "trusted_control_plane_mutations": [
            {
                "node": node,
                "reason": reason,
            }
            for node, reason in sorted(TRUSTED_CONTROL_PLANE_MUTATIONS.items())
        ],
        "python_external_control_commands": python_external_control,
        "powershell_writer_sinks": powershell["writer_sinks"],
        "powershell_execution_inventory": powershell,
        "powershell_guard_failures": guard_failures,
        "known_route_coverage": route_rows,
        "detector_limitations": [
            "Discovery is syntactic over the shipped local import closure and does not execute code.",
            "SQL mutation detection requires a directly supplied mutating SQL literal or constant-only f-string at the call site.",
            "Path-method mutation detection is conservative and requires static path-like receiver evidence.",
            "HTTP network mutation detection conservatively treats calls named post or request as writer sites.",
            "External process creation is conservatively treated as a writer boundary; static Python literals are also scanned for scheduled-task and service control commands.",
            "PowerShell discovery derives the shipped portable PowerShell assets from PORTABLE_INSTALL_ASSETS and records dot-source boundaries; it does not execute PowerShell or recursively interpret sourced code.",
            "PowerShell Start-Process/Invoke-Item, Invoke-Expression/IEX, call-operator, direct script/native command, module import, explicit COM/WMI or native process creation, explicit .NET Process.Start, scheduler COM, service-control, runspace/job/event-action, and reflection primitives are conservatively treated as writer boundaries.",
            "A dynamic PowerShell invocation primitive can be detected and denied when unfenced, but its runtime-computed target or decoded payload cannot in general be resolved statically.",
            "PowerShell guard attribution enforces one bounded top-level guard lifetime and direct intra-file function-call reachability, but remains syntactic and does not prove computed or cross-module calls, alias resolution, module dispatch, or every multiline/here-string control-flow relationship.",
            "Runtime-generated aliases, imported command redefinitions, encrypted or downloaded code, native exports reached through computed reflection, and process creation hidden behind unknown modules remain unobservable statically and require runtime admission plus review.",
        ],
        "coverage_summary": {
            "closure_module_count": len(parsed_modules),
            "closure_direct_mutation_function_count": len(mutation_rows),
            "external_process_mutation_site_count": external_process_site_count,
            "python_external_control_literal_site_count": len(
                python_external_control["literal_sites"]
            ),
            "sink_function_count": len(sink_rows),
            "powershell_sink_count": len(powershell["writer_sinks"]),
            "total_cross_language_sink_count": len(sink_rows)
            + len(powershell["writer_sinks"]),
            "powershell_mutation_scope_count": len(powershell["mutation_scopes"]),
            "powershell_direct_mutation_site_count": len(
                powershell["direct_mutation_sites"]
            ),
            "powershell_execution_site_count": len(powershell["execution_sites"]),
            "powershell_execution_site_counts_by_kind": {
                kind: count
                for kind, count in powershell["site_counts_by_kind"].items()
                if kind
                in {
                    "call_operator",
                    "com_wmi_process_create",
                    "dot_source",
                    "dotnet_process_start",
                    "invoke_expression",
                    "native_command",
                    "native_process_api",
                    "reflective_invocation",
                    "scheduler_com",
                    "service_control_api",
                    "start_process",
                }
            },
            "scheduled_task_mutation_site_count": len(powershell["mutation_sites"]),
            "trusted_control_plane_mutation_count": len(
                TRUSTED_CONTROL_PLANE_MUTATIONS
            ),
            "uncovered_mutation_function_count": len(uncovered),
            "caller_fence_reference_failure_count": len(caller_fence_failures),
        },
    }
    if pinned_unused_sources:
        payload["pinned_unused_sources"] = pinned_unused_sources
    if shell_kit_fence is not None:
        payload["shell_kit_delegated_fence"] = shell_kit_fence
    payload["inventory_sha256"] = _inventory_sha256(payload)
    return payload


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Derive the Container_Audit writer sink inventory."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that the snapshot matches the current derivation.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Rewrite the snapshot file with the current derivation.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    installer = ROOT / "INSTALL_CANONICAL_PORTABLE.ps1"
    source = installer.read_bytes()
    bootstrap_sha = hashlib.sha256((ROOT / "tools/bootstrap_integrity.ps1").read_bytes()).hexdigest()
    pinned, count = re.subn(
        rb"(\$ExpectedBootstrapIntegritySha256 = ')[0-9a-f]{64}(')",
        lambda match: match[1] + bootstrap_sha.encode("ascii") + match[2], source,
    )
    if count != 1:
        raise SystemExit("canonical bootstrap integrity pin declaration is missing or ambiguous")
    if pinned != source:
        if args.write:
            installer.write_bytes(pinned)
        elif args.check:
            raise SystemExit("canonical bootstrap integrity helper pin is stale")
    fence_path = ROOT / "tools/container_writer_fence.ps1"
    fence_source = fence_path.read_bytes()
    if b"ContainerAtomicBootstrapSha256" in fence_source:
        fence_pinned, fence_count = re.subn(
            rb"(\$Script:ContainerAtomicBootstrapSha256 = ')[0-9a-f]{64}(')",
            lambda match: match[1] + bootstrap_sha.encode("ascii") + match[2], fence_source,
        )
        if fence_count != 1:
            raise SystemExit("atomic bootstrap byte pin declaration is missing or ambiguous")
        if fence_pinned != fence_source:
            if args.write:
                fence_path.write_bytes(fence_pinned)
            elif args.check:
                raise SystemExit("atomic bootstrap byte pin is stale")
    payload = derive_inventory(ROOT)
    encoded = _canonical_json_bytes(payload)
    if args.check:
        current = SNAPSHOT_PATH.read_bytes()
        if current != encoded:
            raise SystemExit("container writer sink inventory is stale")
        print(payload["inventory_sha256"])
        return 0
    if args.write:
        SNAPSHOT_PATH.write_bytes(encoded)
    if args.write or args.check:
        bindings = (
            (ROOT / "tools/container_writer_fence.ps1",
             rb"(\$Script:ContainerWriterFenceInventorySha256 = ')[0-9a-f]{64}(')"),
            (ROOT / "tools/container_writer_session_contract.json",
             rb'("writer_inventory_sha256": ")[0-9a-f]{64}(\")'),
        )
        for path, pattern in bindings:
            original = path.read_bytes()
            pinned, count = re.subn(
                pattern,
                lambda match: match[1] + payload["inventory_sha256"].encode("ascii") + match[2],
                original,
            )
            if count != 1:
                raise SystemExit("container writer inventory consumer pin is missing or ambiguous")
            if pinned != original:
                if args.write:
                    path.write_bytes(pinned)
                else:
                    raise SystemExit("container writer inventory consumer pin is stale")
    print(payload["inventory_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Provision a machine-local protected administrator verifier for Container Audit."""

from __future__ import annotations

import argparse
import getpass
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from logistics_runtime_profile import assert_path_has_no_reparse_components  # noqa: E402
from protected_admin import (  # noqa: E402
    MAX_PROTECTED_ADMIN_PROFILE_BYTES,
    PROTECTED_ADMIN_PROFILE_SCHEMA,
    PROTECTED_ADMIN_ROLE,
    ProtectedAdminProfileError,
    build_protected_admin_profile,
    default_protected_admin_profile_path,
    load_protected_admin_profile,
)

__all__ = [
    "build_parser",
    "install_protected_admin_profile",
    "load_installed_profile",
    "main",
]


_WINDOWS_PRINCIPAL_RE = re.compile(
    r"^(?:S-\d+(?:-\d+)+|[A-Za-z0-9_.@-]+(?:\\[A-Za-z0-9_. @-]+)?)$"
)
_SID_RE = re.compile(r"^S-\d+(?:-\d+)+$")
_BROAD_READER_NAMES = frozenset({
    "authenticated users",
    "builtin\\guests",
    "builtin\\users",
    "creator owner",
    "everyone",
    "guests",
    "interactive",
    "network",
    "service",
    "users",
})
_DISALLOWED_READER_SIDS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-3-0",       # Creator Owner
    "S-1-5-2",       # Network
    "S-1-5-4",       # Interactive
    "S-1-5-6",       # Service
    "S-1-5-11",      # Authenticated Users
    "S-1-5-18",      # SYSTEM (already an administrator ACE)
    "S-1-5-32-544",  # Administrators (already an administrator ACE)
    "S-1-5-32-545",  # Users
    "S-1-5-32-546",  # Guests
    "S-1-5-113",     # Local account
    "S-1-5-114",     # Local account and member of Administrators
})
_ACL_TARGET_ENV = "KMTECH_PROTECTED_ADMIN_ACL_TARGET"
_ACL_SDDL_ENV = "KMTECH_PROTECTED_ADMIN_ACL_SDDL"
_READER_PRINCIPAL_ENV = "KMTECH_PROTECTED_ADMIN_READER_PRINCIPAL"


def _run_powershell(script: str, *, environment: dict[str, str]) -> str:
    if os.name != "nt":
        raise RuntimeError(
            "protected administrator ACL hardening is available only on Windows"
        )
    child_environment = os.environ.copy()
    child_environment.update(environment)
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=child_environment,
    )
    if completed.returncode != 0:
        raise RuntimeError("protected administrator Windows security operation failed")
    return completed.stdout.strip()


def _validate_reader_principal(reader_principal: str) -> str:
    principal = str(reader_principal or "").strip()
    if (
        not principal
        or len(principal) > 200
        or _WINDOWS_PRINCIPAL_RE.fullmatch(principal) is None
        or principal.casefold() in _BROAD_READER_NAMES
    ):
        raise ValueError("reader_principal must name one narrowly scoped Windows user")
    return principal


def _resolve_reader_sid(reader_principal: str) -> str:
    """Resolve and prove the reader is a user account, not a broad group."""
    principal = _validate_reader_principal(reader_principal)
    script = r"""
$ErrorActionPreference = 'Stop'
$principal = [Environment]::GetEnvironmentVariable('KMTECH_PROTECTED_ADMIN_READER_PRINCIPAL')
try {
    if ($principal -match '^S-\d+(?:-\d+)+$') {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($principal)
    } else {
        $account = [System.Security.Principal.NTAccount]::new($principal)
        $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
    }
    $escapedSid = $sid.Value.Replace("'", "''")
    $users = @(
        Get-CimInstance -ClassName Win32_UserAccount -Filter "SID='$escapedSid'"
    )
    if ($users.Count -ne 1) {
        throw 'reader principal must resolve to exactly one Windows user account'
    }
    [Console]::Out.Write($sid.Value)
} catch {
    [Console]::Error.Write('reader principal validation failed')
    exit 1
}
"""
    sid = _run_powershell(
        script,
        environment={_READER_PRINCIPAL_ENV: principal},
    )
    if _SID_RE.fullmatch(sid) is None or sid in _DISALLOWED_READER_SIDS:
        raise ValueError("reader_principal must resolve to one narrowly scoped user")
    return sid


def _expected_acl_sddl(reader_sid: str, *, directory: bool) -> str:
    if _SID_RE.fullmatch(reader_sid) is None or reader_sid in _DISALLOWED_READER_SIDS:
        raise ValueError("reader SID is invalid or too broad")
    if directory:
        return (
            "D:PAI"
            "(A;OICI;FA;;;SY)"
            "(A;OICI;FA;;;BA)"
            f"(A;OICI;FR;;;{reader_sid})"
        )
    return "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)" f"(A;;FR;;;{reader_sid})"


def _apply_exact_acl(path: Path, reader_sid: str, *, directory: bool) -> None:
    target = assert_path_has_no_reparse_components(
        path,
        label="protected administrator ACL target",
    )
    sddl = _expected_acl_sddl(reader_sid, directory=directory)
    script = r"""
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('KMTECH_PROTECTED_ADMIN_ACL_TARGET')
$sddl = [Environment]::GetEnvironmentVariable('KMTECH_PROTECTED_ADMIN_ACL_SDDL')
try {
    $acl = Get-Acl -LiteralPath $target
    $acl.SetSecurityDescriptorSddlForm(
        $sddl,
        [System.Security.AccessControl.AccessControlSections]::Access
    )
    Set-Acl -LiteralPath $target -AclObject $acl
} catch {
    [Console]::Error.Write('exact ACL application failed')
    exit 1
}
"""
    _run_powershell(
        script,
        environment={_ACL_TARGET_ENV: str(target), _ACL_SDDL_ENV: sddl},
    )


def _verify_exact_acl(path: Path, reader_sid: str, *, directory: bool) -> None:
    target = assert_path_has_no_reparse_components(
        path,
        label="protected administrator ACL target",
    )
    sddl = _expected_acl_sddl(reader_sid, directory=directory)
    script = r"""
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('KMTECH_PROTECTED_ADMIN_ACL_TARGET')
$sddl = [Environment]::GetEnvironmentVariable('KMTECH_PROTECTED_ADMIN_ACL_SDDL')
try {
    $actualAcl = Get-Acl -LiteralPath $target
    $actual = $actualAcl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Access
    )
    if ((Get-Item -LiteralPath $target -Force).PSIsContainer) {
        $expectedAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        $expectedAcl = [System.Security.AccessControl.FileSecurity]::new()
    }
    $expectedAcl.SetSecurityDescriptorSddlForm(
        $sddl,
        [System.Security.AccessControl.AccessControlSections]::Access
    )
    $expected = $expectedAcl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::Access
    )
    if ($actual -cne $expected) {
        throw 'ACL readback differs from the exact allow-list'
    }
} catch {
    [Console]::Error.Write('exact ACL verification failed')
    exit 1
}
"""
    _run_powershell(
        script,
        environment={_ACL_TARGET_ENV: str(target), _ACL_SDDL_ENV: sddl},
    )


def _harden_profile_directory(path: Path, reader_sid: str) -> Path:
    directory = assert_path_has_no_reparse_components(
        path,
        label="protected administrator profile directory",
    )
    directory.mkdir(parents=True, exist_ok=True)
    directory = assert_path_has_no_reparse_components(
        directory,
        label="protected administrator profile directory",
    )
    _apply_exact_acl(directory, reader_sid, directory=True)
    _verify_exact_acl(directory, reader_sid, directory=True)
    return directory


def _harden_profile_file(path: Path, reader_sid: str) -> Path:
    target = assert_path_has_no_reparse_components(
        path,
        label="protected administrator profile file",
    )
    _apply_exact_acl(target, reader_sid, directory=False)
    _verify_exact_acl(target, reader_sid, directory=False)
    return target


def _write_and_sync(fd: int, data: bytes) -> None:
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _atomic_write(path: Path, data: bytes, reader_sid: str) -> None:
    """Replace *path* from an exclusively created, empty, pre-hardened file."""
    fd = -1
    temporary = path.parent / ".uncreated-protected-admin-profile.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    for _attempt in range(32):
        temporary = path.with_name(
            f".{path.name}.{secrets.token_hex(16)}.tmp"
        )
        try:
            fd = os.open(temporary, flags, 0o600)
            break
        except FileExistsError:
            continue
    if fd < 0:
        raise RuntimeError(
            "protected administrator temporary profile could not be created exclusively"
        )
    fd_open = True
    try:
        temporary = assert_path_has_no_reparse_components(
            temporary,
            label="protected administrator temporary profile",
        )
        if temporary.stat().st_size != 0:
            raise RuntimeError("protected administrator temporary profile is not empty")
        _harden_profile_file(temporary, reader_sid)
        _write_and_sync(fd, data)
        fd_open = False
        _verify_exact_acl(temporary, reader_sid, directory=False)
        assert_path_has_no_reparse_components(
            path,
            label="protected administrator profile",
        )
        os.replace(temporary, path)
        assert_path_has_no_reparse_components(
            path,
            label="protected administrator profile",
        )
    finally:
        if fd_open:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _profile_bytes(payload: dict[str, object]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def load_installed_profile(
    path: str | os.PathLike[str],
    *,
    expected: dict[str, object] | None = None,
) -> dict[str, object]:
    try:
        payload = load_protected_admin_profile(path)
    except ProtectedAdminProfileError as exc:
        raise RuntimeError("protected administrator profile readback failed") from exc
    if expected is not None and payload != expected:
        raise RuntimeError("protected administrator profile exact readback failed")
    return payload


def _read_exact_profile_bytes(path: Path, *, expected_size: int) -> bytes:
    target = assert_path_has_no_reparse_components(
        path,
        label="protected administrator profile",
    )
    if expected_size < 1 or expected_size > MAX_PROTECTED_ADMIN_PROFILE_BYTES:
        raise RuntimeError("protected administrator expected profile size is invalid")
    try:
        with target.open("rb") as handle:
            data = handle.read(expected_size + 1)
    except OSError as exc:
        raise RuntimeError(
            "protected administrator profile byte readback failed"
        ) from exc
    assert_path_has_no_reparse_components(
        target,
        label="protected administrator profile",
    )
    if len(data) != expected_size:
        raise RuntimeError("protected administrator profile byte readback differs")
    return data


def _restore_previous_profile(
    target: Path,
    payload: dict[str, object],
    raw_payload: bytes,
    reader_sid: str,
) -> None:
    _atomic_write(target, raw_payload, reader_sid)
    _harden_profile_file(target, reader_sid)
    load_installed_profile(target, expected=payload)
    if _read_exact_profile_bytes(
        target,
        expected_size=len(raw_payload),
    ) != raw_payload:
        raise RuntimeError("protected administrator rollback byte readback failed")


def _remove_or_invalidate_failed_profile(target: Path, reader_sid: str) -> None:
    """Ensure a failed first install cannot leave an authenticating profile."""
    checked = assert_path_has_no_reparse_components(
        target,
        label="protected administrator profile",
    )
    try:
        checked.unlink(missing_ok=True)
    except OSError:
        _atomic_write(checked, b"", reader_sid)
        _harden_profile_file(checked, reader_sid)
        if checked.stat().st_size != 0:
            raise RuntimeError(
                "protected administrator fail-closed marker is invalid"
            )
    if checked.exists():
        try:
            load_installed_profile(checked)
        except RuntimeError:
            return
        raise RuntimeError("protected administrator failed profile remains usable")


def install_protected_admin_profile(
    candidate: object | None = None,
    *,
    profile_path: str | os.PathLike[str] | None = None,
    reader_principal: str = "",
    dry_run: bool = False,
    replace: bool = False,
) -> dict[str, Any]:
    target = assert_path_has_no_reparse_components(
        profile_path or default_protected_admin_profile_path(),
        label="protected administrator profile",
    )
    summary: dict[str, Any] = {
        "status": "dry-run" if dry_run else "installed",
        "schema_version": PROTECTED_ADMIN_PROFILE_SCHEMA,
        "role": PROTECTED_ADMIN_ROLE,
        "profile_path": str(target),
    }
    if dry_run:
        if candidate is not None:
            build_protected_admin_profile(candidate)
        return summary
    if target.exists() and not replace:
        raise FileExistsError(
            "protected administrator profile already exists; use --replace for intentional reprovisioning"
        )
    reader_sid = _resolve_reader_sid(reader_principal)
    payload = build_protected_admin_profile(candidate)
    payload_bytes = _profile_bytes(payload)
    _harden_profile_directory(target.parent, reader_sid)
    target = assert_path_has_no_reparse_components(
        target,
        label="protected administrator profile",
    )

    previous_payload: dict[str, object] | None = None
    previous_raw_payload: bytes | None = None
    if target.exists():
        if not replace:
            raise FileExistsError(
                "protected administrator profile appeared during provisioning"
            )
        _harden_profile_file(target, reader_sid)
        try:
            previous_payload = load_installed_profile(target)
            previous_raw_payload = _read_exact_profile_bytes(
                target,
                expected_size=target.stat().st_size,
            )
            load_installed_profile(target, expected=previous_payload)
        except RuntimeError:
            previous_payload = None
            previous_raw_payload = None

    replacement_attempted = False
    try:
        replacement_attempted = True
        _atomic_write(target, payload_bytes, reader_sid)
        _harden_profile_file(target, reader_sid)
        load_installed_profile(target, expected=payload)
        if _read_exact_profile_bytes(
            target,
            expected_size=len(payload_bytes),
        ) != payload_bytes:
            raise RuntimeError(
                "protected administrator profile byte readback differs"
            )
    except Exception as install_error:
        if replacement_attempted:
            if previous_payload is not None and previous_raw_payload is not None:
                try:
                    _restore_previous_profile(
                        target,
                        previous_payload,
                        previous_raw_payload,
                        reader_sid,
                    )
                except Exception as restore_error:
                    try:
                        _remove_or_invalidate_failed_profile(target, reader_sid)
                    except Exception as fail_closed_error:
                        raise RuntimeError(
                            "protected administrator reprovision failed, restoration failed, and invalidation failed"
                        ) from fail_closed_error
                    raise RuntimeError(
                        "protected administrator reprovision failed; previous profile could not be restored and the target was invalidated"
                    ) from restore_error
            else:
                try:
                    _remove_or_invalidate_failed_profile(target, reader_sid)
                except Exception as cleanup_error:
                    raise RuntimeError(
                        "protected administrator install failed and cleanup failed"
                    ) from cleanup_error
        raise install_error
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install a machine-local offline administrator verifier.",
        allow_abbrev=False,
    )
    parser.add_argument("--profile-path", default=default_protected_admin_profile_path())
    parser.add_argument("--reader-principal", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args, unknown = build_parser().parse_known_args(argv)
    if unknown:
        print("BLOCKED: unsupported command-line argument", file=sys.stderr)
        return 2
    if not args.dry_run and not str(args.reader_principal or "").strip():
        print("BLOCKED: --reader-principal is required for an actual install", file=sys.stderr)
        return 2

    first = ""
    second = ""
    try:
        try:
            first = getpass.getpass("Protected administrator code: ")
            second = getpass.getpass("Confirm protected administrator code: ")
        except (AttributeError, EOFError, KeyboardInterrupt):
            print("BLOCKED: protected administrator hidden input failed", file=sys.stderr)
            return 2
        if not hmac.compare_digest(first.encode("utf-8"), second.encode("utf-8")):
            print("BLOCKED: credential entries do not match", file=sys.stderr)
            return 2
        try:
            report = install_protected_admin_profile(
                candidate=first,
                profile_path=args.profile_path,
                reader_principal=args.reader_principal,
                dry_run=args.dry_run,
                replace=args.replace,
            )
        except Exception as exc:
            print(f"BLOCKED: {exc.__class__.__name__}", file=sys.stderr)
            return 2
    finally:
        first = ""
        second = ""
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

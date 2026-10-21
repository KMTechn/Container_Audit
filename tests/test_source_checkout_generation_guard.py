"""Exercise the actual source identity guard without changing a checkout."""
import subprocess

import pytest

import data_generation_guard as guard


@pytest.mark.parametrize("status", ("", "?? additional-untracked.py\n", " M Container_Audit.py\n"),
                         ids=("clean", "extra-untracked", "tracked-change"))
def test_source_checkout_rejects_every_other_status_row(monkeypatch, status):
    monkeypatch.setattr(guard.sys, "frozen", False, raising=False)
    monkeypatch.setattr(guard, "_portable_runtime_release", lambda: None)
    context = guard._SUPPORT_REMOVAL_RELEASE.set(None)
    calls = []
    build = "a" * 40

    def metadata(command, **kwargs):
        assert command[:3] == ["git", "--no-optional-locks", "-C"]
        assert kwargs["stderr"] == subprocess.DEVNULL and kwargs["text"] is True
        calls.append(command[4:])
        if command[4:] == ["rev-parse", "HEAD^{commit}"]:
            return build + "\n"
        assert command[4:] == ["status", "--porcelain"]
        return status

    monkeypatch.setattr(guard.subprocess, "check_output", metadata)
    try:
        if status:
            with pytest.raises(ValueError, match="^running source is not the release commit$"):
                guard._runtime_release()
        else:
            release = guard._runtime_release()
            assert release["build_id"] == build
            assert release["compatibility_verified"] is False
        assert calls == [["rev-parse", "HEAD^{commit}"], ["status", "--porcelain"]]
    finally:
        guard._SUPPORT_REMOVAL_RELEASE.reset(context)

"""A frozen source must still produce a writable disposable test packet."""
import stat

from tests import test_zero_touch_installer as installer


def test_portable_fixture_can_customize_copies_of_readonly_source(tmp_path, monkeypatch):
    controls = {
        "PORTABLE_INSTALLER": "INSTALL_CANONICAL_PORTABLE.ps1",
        "INSTALLER": "INSTALL_THIS_PC.ps1",
        "INTEGRITY_HELPER": "tools/bootstrap_integrity.ps1",
        "WRITER_SESSION_ADAPTER": "tools/container_writer_session.ps1",
        "WRITER_SESSION_CONTRACT": "tools/container_writer_session_contract.json",
        "WRITER_FENCE_HELPER": "tools/container_writer_fence.ps1",
        "WRITER_SINK_INVENTORY": "tools/container_writer_sink_inventory.json",
    }
    original = {}
    for name, relative in controls.items():
        source = tmp_path / "frozen-source" / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        payload = getattr(installer, name).read_bytes()
        source.write_bytes(payload)
        source.chmod(stat.S_IREAD)
        original[source] = payload
        monkeypatch.setattr(installer, name, source)

    packet = installer._portable_release_fixture(tmp_path, directory="packet")
    for relative in controls.values():
        source = tmp_path / "frozen-source" / relative
        copied = packet / relative
        assert copied.read_bytes() == original[source]
        # Opening the disposable copy for customization must work on Windows.
        customized = original[source] + b"\n"
        copied.write_bytes(customized)
        assert copied.read_bytes() == customized
        assert copied.stat().st_mode & stat.S_IWRITE

    for source, payload in original.items():
        assert source.read_bytes() == payload
        assert not source.stat().st_mode & stat.S_IWRITE

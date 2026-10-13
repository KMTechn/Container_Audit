"""Support removal accepts the records emitted by the installation writers."""
from pathlib import Path
from types import SimpleNamespace
import json
import shutil

import pytest
import auto_update as update
import current_user_onboarding as onboarding
import data_generation_guard as guard
from tests.test_support_packet_removal import (
    _record_installed_packet, support_removal_packets,
)
from tests.test_support_removal_after_update import updated_packets
from tests.test_portable_data_generation import signed_packet, signed_proof


@pytest.fixture
def initial_packets(tmp_path, monkeypatch, support_removal_packets):
    seed = support_removal_packets
    managed = tmp_path / 'initial-managed'
    fixed = managed / 'current'
    shutil.copytree(seed.installed, fixed, ignore=shutil.ignore_patterns('__pycache__'))
    _record_installed_packet(tmp_path, fixed)
    assert not (seed.support / 'bootstrap-integrity.json').exists()
    sha = update.read_json(fixed / 'portable-manifest.json')['source_commit']
    active = managed / 'versions' / sha
    shutil.copytree(fixed, active)
    control = managed / 'update-control'
    stage = managed / 'stage'
    control.mkdir()
    stage.mkdir()
    update.write_json_durable(control / "policy.json", {
        "schema": "container-audit-startup-update-policy-v1",
        "operator_sid": seed.subject, "operator_local_app_data": str(tmp_path / "operator"),
        "staging_root": str(stage), "channel": "stable",
        "feed_url": "/".join(("https:", "", "example.invalid", "feed")),
    })
    # INSTALL_THIS_PC writes an ID only into the active pointer.
    update.write_json_durable(control / 'active.json', {
        'schema': update.SCHEMA, 'sha': sha, 'transition_id': 'CANONICAL_INSTALL',
    })
    update.write_json_durable(control / 'transition.json', {
        'schema': update.SCHEMA, 'phase': 'DEFERRED',
        'deferred_at': '2026-10-12T00:00:00Z', 'reason': 'canonical installation',
        'failed_shas': [],
    })
    def remove(packet=seed.support):
        monkeypatch.setattr(guard, "__file__", str(packet / "app/data_generation_guard.py"))
        return onboarding.remove_current_user_setup(
            fixed / "app", environ=seed.environment,
            autostart_remover=lambda: seed.observed.append("autostart") or {"status": "ABSENT"},
            relay_stopper=lambda _root: seed.observed.append("relay") or {"status": "ABSENT"},
        )
    return SimpleNamespace(seed=seed, fixed=fixed, active=active, control=control, remove=remove)


def test_initial_install_records_allow_same_release_support_removal(initial_packets, monkeypatch):
    packets = initial_packets
    selected = []
    original = update.version_bundle
    def version_bundle(control, sha):
        root = original(control, sha)
        selected.append(root)
        return root
    monkeypatch.setattr(update, 'version_bundle', version_bundle)
    pointer = update.read_json(packets.control / 'active.json')
    state = update.read_json(packets.control / 'transition.json')
    assert pointer['transition_id'] == 'CANONICAL_INSTALL'
    assert 'transition_id' not in state
    event = packets.seed.event.read_bytes()
    assert packets.remove()['status'] == 'PASS_DATA_PRESERVED'
    assert packets.seed.event.read_bytes() == event
    assert selected == [packets.active]


def test_supported_placement_records_allow_candidate_source_removal(tmp_path, updated_packets):
    packets = updated_packets
    event = packets.seed.event.read_bytes()
    before = {path: path.read_bytes() for path in packets.markers}
    # The reinstall's pre-placement removal (5278) runs verified active B.
    assert packets.remove(packets.active)['status'] == 'PASS_DATA_PRESERVED'
    candidate_sha = update.read_json(packets.candidate / 'portable-manifest.json')['source_commit']
    placed = packets.fixed.parent / 'versions' / candidate_sha
    shutil.copytree(packets.candidate, placed, ignore=shutil.ignore_patterns('__pycache__'))
    _record_installed_packet(tmp_path, placed)
    # Supported placement writes C plus its transaction ID, then a DEFERRED
    # state with no transaction ID (INSTALL_THIS_PC supported-placement writer).
    update.write_json_durable(packets.control / 'active.json', {
        'schema': update.SCHEMA, 'sha': candidate_sha,
        'transition_id': 'support-placement-transaction',
    })
    update.write_json_durable(packets.control / 'transition.json', {
        'schema': update.SCHEMA, 'phase': 'DEFERRED',
        'deferred_at': '2026-10-12T00:00:00Z',
        'reason': 'supported canonical active-version placement', 'failed_shas': [],
    })
    assert 'transition_id' not in update.read_json(packets.control / 'transition.json')
    # The post-placement (5478) and rollback cleanup (5994) use source C,
    # retaining the installed A logical root and the B data floor.
    assert packets.remove(packets.candidate)['status'] == 'PASS_DATA_PRESERVED'
    assert packets.remove(packets.candidate)['status'] == 'PASS_DATA_PRESERVED'
    assert packets.seed.event.read_bytes() == event
    assert all(path.read_bytes() == value for path, value in before.items())

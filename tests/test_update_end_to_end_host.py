"""Opt-in full-process reproduction of the frozen 120 update confirmation race."""
import os
from pathlib import Path

import pytest

from tests import _update_host as host


def test_ready_diagnostic(tmp_path):
    packet = os.environ.get('CONTAINER_AUDIT_HOST_TEST_PACKET')
    if not packet:
        pytest.skip('authenticated frozen 120 packet required')
    from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair
    with P256KeyPair.generate() as signer:
        config = host.prepare(tmp_path, Path(__file__).resolve().parents[1], Path(packet), signer,
                              departure=host.departure_identity())
        try:
            host.ready(config)
            helper = host.launch(config, 'helper-probe', ['--apply-prepared'])
            assert helper.wait() == 0, 'inspect actual full-helper diagnostics'
        finally:
            host.stop_owned_relays(config)


def test_prepare_121_and_initial_120_ready(tmp_path):
    packet = os.environ.get('CONTAINER_AUDIT_HOST_TEST_PACKET')
    if not packet:
        pytest.skip('authenticated frozen 120 packet required')
    from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair
    with P256KeyPair.generate() as signer:
        config = host.prepare(tmp_path, Path(__file__).resolve().parents[1], Path(packet), signer,
                              departure=host.departure_identity())
        host.prepare_update(config, signer)
        try:
            host.ready(config)
        finally:
            host.stop_owned_relays(config)


@pytest.mark.parametrize('delay', [0, 15], ids=['natural', 'slow15'])
def test_update_120_to_121(tmp_path, delay):
    packet = os.environ.get('CONTAINER_AUDIT_HOST_TEST_PACKET')
    if not packet:
        pytest.skip('authenticated frozen 120 packet required')
    from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair
    with P256KeyPair.generate() as signer:
        config = host.prepare(tmp_path, Path(__file__).resolve().parents[1], Path(packet), signer,
                              slow_observe=delay, departure=host.departure_identity())
        target = host.prepare_update(config, signer)
        try:
            host.ready(config)
            result = host.run_chain(config, target)
            assert result['confirmed'], 'inspect chain-result.json: actual SYSTEM confirmation did not complete'
        finally:
            host.stop_owned_relays(config)

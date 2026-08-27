import sys

import container_audit_product_host as product_host
from tools import direct_sync_relay_runner


def test_non_product_arguments_continue_to_gui_startup():
    assert product_host.dispatch_product_mode([]) is None
    assert product_host.dispatch_product_mode(["--ordinary-app-argument"]) is None


def test_relay_mode_reuses_main_process_and_forwards_arguments(monkeypatch):
    observed = []

    def fake_main(arguments):
        observed.append(list(arguments))
        return 17

    monkeypatch.setattr(direct_sync_relay_runner, "main", fake_main)

    result = product_host.dispatch_product_mode(
        [product_host.DIRECT_SYNC_RELAY_MODE, "--db-path", "queue.sqlite3"]
    )

    assert result == 17
    assert observed == [["--db-path", "queue.sqlite3"]]


def test_windowed_host_supplies_and_restores_output_streams(monkeypatch):
    observed = []

    def fake_main(arguments):
        observed.append((sys.stdout is not None, sys.stderr is not None, list(arguments)))
        return 0

    monkeypatch.setattr(direct_sync_relay_runner, "main", fake_main)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)

    assert product_host.dispatch_product_mode([product_host.DIRECT_SYNC_RELAY_MODE]) == 0
    assert observed == [(True, True, [])]
    assert sys.stdout is None
    assert sys.stderr is None

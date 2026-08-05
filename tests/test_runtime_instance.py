from __future__ import annotations

import os

import pytest

from runtime_instance import acquire_runtime_instance, runtime_mutex_name


def test_runtime_mutex_name_is_stable_and_data_root_scoped(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"

    assert runtime_mutex_name(first_root) == runtime_mutex_name(first_root / ".")
    assert runtime_mutex_name(first_root) != runtime_mutex_name(second_root)
    assert str(first_root) not in runtime_mutex_name(first_root)
    assert runtime_mutex_name(first_root).startswith("Global\\KMTech.ContainerAudit.")


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex contract")
def test_same_pc_same_data_root_allows_only_one_runtime(tmp_path):
    first = acquire_runtime_instance(tmp_path)
    assert first is not None
    try:
        assert acquire_runtime_instance(tmp_path) is None
    finally:
        first.release()

    replacement = acquire_runtime_instance(tmp_path)
    assert replacement is not None
    replacement.release()


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex contract")
def test_same_pc_different_data_roots_do_not_collide(tmp_path):
    first = acquire_runtime_instance(tmp_path / "first")
    second = acquire_runtime_instance(tmp_path / "second")
    assert first is not None
    assert second is not None
    first.release()
    second.release()

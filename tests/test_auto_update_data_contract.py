"""Contract compatibility checks against actual stored DDL and serialized data."""
from pathlib import Path
import ast
import re
import shutil

import pytest
import auto_update as updates


def test_same_length_exchange_ddl_change_is_preserved_as_compatibility_evidence(tmp_path):
    from tools import derive_container_writer_sinks as derive

    repository = Path(updates.__file__).resolve().parent
    application = tmp_path / 'app'
    shutil.copytree(repository, application, ignore=shutil.ignore_patterns('.git', '__pycache__', '.pytest_cache'))
    original_inventory = derive.derive_inventory(application)['inventory_sha256']
    original_contract = updates.data_api_contract_sha256(application)
    path = application / 'transfer_member_exchange.py'
    source = path.read_bytes()
    original = b'CHECK(pair_count BETWEEN 1 AND 2)'
    changed = b'CHECK(pair_count BETWEEN 1 AND 1)'
    assert source.count(original) == 1
    path.write_bytes(source.replace(original, changed))
    assert path.stat().st_size == len(source)
    changed_inventory = derive.derive_inventory(application)['inventory_sha256']
    assert changed_inventory == original_inventory
    changed_contract = updates.data_api_contract_sha256(application)
    assert changed_contract != original_contract, 'Actual exchange DDL omitted from compatibility hash'
    assert (repository / 'transfer_member_exchange.py').read_bytes() == source


def test_all_repository_ddl_owners_are_bound_to_data_contract():
    repository = Path(updates.__file__).resolve().parent
    ddl = re.compile(r'\b(?:CREATE|ALTER|DROP)\s+(?:TEMP(?:ORARY)?\s+)?(?:TABLE|INDEX|TRIGGER)\b', re.I)
    owners = set()
    for path in [*repository.glob('*.py'), *repository.joinpath('tools').glob('*.py')]:
        tree = ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path))
        if any(isinstance(node, ast.Constant) and isinstance(node.value, str) and ddl.search(node.value)
               for node in ast.walk(tree)):
            owners.add(path.relative_to(repository).as_posix())
    assert owners, 'DDL census found no source owners'
    assert owners <= set(updates.DATA_API_FILES), f'Unbound DDL owners: {sorted(owners - set(updates.DATA_API_FILES))}'

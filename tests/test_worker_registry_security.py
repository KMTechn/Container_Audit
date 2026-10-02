import json

import pytest

from worker_registry import WorkerRegistry


@pytest.mark.parametrize(
    "name,accepted",
    [
        ("", False),
        (" ", False),
        ("bad/name", True),
        ("bad:name", True),
        ("bad\"name", True),
        ("bad|name", True),
        ("=SUM(A1:A2)", True),
        ("+cmd|' /C calc'!A0", True),
        ("-1+2", True),
        ("@HYPERLINK(\"https://example.invalid\")", True),
        ("\t=SUM(A1:A2)", False),
        ("홍\n길동", False),
        ("홍\r길동", False),
        ("홍\x00길동", False),
    ],
)
def test_worker_registry_rejects_formula_and_control_character_names(tmp_path, name, accepted):
    registry = WorkerRegistry(str(tmp_path / "worker_registry.json"))

    # Retain every original input; stage one changes only visible-name restrictions.
    if accepted:
        assert registry.register(name) == name.strip()
    else:
        with pytest.raises(ValueError):
            registry.register(name)


def test_worker_registry_sanitizes_formula_and_control_character_entries_from_disk(tmp_path):
    registry_path = tmp_path / "worker_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "workers": [
                    {"name": "=SUM(A1:A2)", "active": True},
                    {"name": "홍\n길동", "active": True},
                    {"name": "안전작업자", "active": True},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    # Stage-one name rules accept visible text without alphabet/filename restrictions.
    assert WorkerRegistry(str(registry_path)).list_workers() == ["=SUM(A1:A2)", "안전작업자"]

import json

import pytest

from worker_registry import WorkerRegistry


@pytest.mark.parametrize(
    "name",
    [
        "=SUM(A1:A2)",
        "+cmd|' /C calc'!A0",
        "-1+2",
        "@HYPERLINK(\"https://example.invalid\")",
        "\t=SUM(A1:A2)",
        "홍\n길동",
        "홍\r길동",
        "홍\x00길동",
    ],
)
def test_worker_registry_rejects_formula_and_control_character_names(tmp_path, name):
    registry = WorkerRegistry(str(tmp_path / "worker_registry.json"))

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

    assert WorkerRegistry(str(registry_path)).list_workers() == ["안전작업자"]

"""Mixed relay status keeps machine bytes and refuses secret-bearing writes."""
import importlib
import json

import pytest


WRITERS = (
    "direct_sync_runtime",
    "direct_sync_push",
    "user_relay",
    "container_audit_product_host",
    "tools.direct_sync_relay_operator",
)


@pytest.mark.parametrize("module_name", WRITERS)
def test_mixed_status_preserves_large_unicode_machine_bytes(tmp_path, module_name):
    module = importlib.import_module(module_name)
    payload = {"worker_id": "작업자", "identity": {"binding": "자료" * 24000}}
    expected = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    assert len(expected) > 65536
    path = tmp_path / "status.json"

    module._write_json_atomic(path, payload)

    assert path.read_bytes() == expected
    assert json.loads(path.read_bytes()) == payload


@pytest.mark.parametrize("module_name", WRITERS)
def test_mixed_status_secret_rejection_preserves_preimage_and_creates_no_temp(tmp_path, monkeypatch, module_name):
    module = importlib.import_module(module_name)
    value = 'synthetic405\\"비밀'
    monkeypatch.setenv("WORKER_ANALYSIS_LOGISTICS_API_TOKEN", value)
    path = tmp_path / "status.json"
    original = b'{"worker_id":"prior"}\n'
    path.write_bytes(original)
    before = set(tmp_path.iterdir())

    with pytest.raises(ValueError, match="^MACHINE_METADATA_SECRET_DETECTED$"):
        module._write_json_atomic(path, {"worker_id": value, "identity": {"worker_id": value}})

    assert path.read_bytes() == original
    assert set(tmp_path.iterdir()) == before
    missing_parent = tmp_path / "absent" / "status.json"
    with pytest.raises(ValueError, match="^MACHINE_METADATA_SECRET_DETECTED$"):
        module._write_json_atomic(missing_parent, {"worker_id": value})
    assert not missing_parent.parent.exists()


def test_operator_cli_secret_rejection_does_not_replace_status_with_error(tmp_path, monkeypatch, capsys):
    from auto_update import run_support_main
    from tests.test_direct_sync_runtime import make_config
    from tools import direct_sync_relay_operator as operator

    value = "synthetic405-known-environment-value"
    report = {"status": "PASS", "operator_id": "operator-normal"}
    monkeypatch.setattr(operator, "operator_status", lambda **kwargs: report)
    config = make_config(tmp_path)
    path = tmp_path / "reports" / "status.json"
    arguments = ["status", "--db-path", str(config.db_path), "--report-path", str(path)]
    assert operator.main(arguments) == 0
    original = path.read_bytes()
    capsys.readouterr()
    monkeypatch.setenv("WORKER_ANALYSIS_LOGISTICS_API_TOKEN", value)
    report["operator_id"] = value

    result = run_support_main(lambda: operator.main(arguments), stage="relay_operator")

    assert result != 0
    assert path.read_bytes() == original
    captured = capsys.readouterr()
    assert value not in captured.out + captured.err
    public = json.loads(captured.err.split("=", 1)[1])
    assert public["reason_code"] == "SUPPORT_FAILURE"
    assert public["exception_type"] == "builtins.ValueError"

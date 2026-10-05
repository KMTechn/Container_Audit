import hashlib
import json
from pathlib import Path

from tools.build_portable_release_candidate import _write_update_key_config
from vendor.kmtech_zero_pe.release_signature import validate_public_key_config


def test_approved_ca_public_configuration_uses_existing_verifier_and_packet_format(tmp_path):
    path = Path(__file__).resolve().parents[1] / "update-manifest-key-config.json"
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "d7fb6ecb06b23ecf2fceea6c893c8d1162dad302720ab0e97d19dfae6368d1e5"
    configuration = json.loads(raw)
    assert configuration["schema"] == "container-audit-update-key-config-v1"
    public = json.dumps(configuration["manifest_public_key"])
    validate_public_key_config(public)
    assert _write_update_key_config(tmp_path, public) == hashlib.sha256(raw).hexdigest()
    assert (tmp_path / path.name).read_bytes() == raw

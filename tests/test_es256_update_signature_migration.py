"""Test-only ES256 fixtures for the update-manifest migration contract."""

import json

import pytest

import update_service
from vendor.kmtech_zero_pe.cng_p256 import P256KeyPair


def test_es256_manifest_positive_tamper_and_missing_signature():
    manifest = {
        "schema_version": "kmtech-private-update-manifest-v1",
        "manifest_version": 1,
        "signature_version": "es256-v1",
        "app_id": "Container_Audit",
    }
    payload = update_service.canonical_manifest_bytes(manifest)
    with P256KeyPair.generate() as private_key:
        signature = private_key.sign_es256(payload)
        public_config = json.dumps(private_key.public_jwk, sort_keys=True)

    update_service.verify_update_manifest_signature(manifest, signature, public_config)

    tampered = dict(manifest, app_id="tampered")
    with pytest.raises(ValueError, match="서명 검증"):
        update_service.verify_update_manifest_signature(tampered, signature, public_config)
    with pytest.raises(ValueError, match="서명 검증"):
        update_service.verify_update_manifest_signature(manifest, b"", public_config)

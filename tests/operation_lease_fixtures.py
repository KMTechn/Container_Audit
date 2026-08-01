import base64
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)

from terminal_operation_lease import (
    ARTIFACT_CONTRACT_VERSION,
    JWS_TYPE,
    KEYRING_CONTRACT_VERSION,
    LEASE_CONTRACT_VERSION,
    TRANSFER_OPERATION,
    canonical_hash,
    canonical_json_bytes,
    jwk_thumbprint,
    physical_qr_sha256,
    utc_text,
)


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _public_jwk(key):
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }


def _sign(key, kid, claims):
    header = {"alg": "ES256", "kid": kid, "typ": JWS_TYPE}
    encoded_header = _b64(canonical_json_bytes(header))
    encoded_payload = _b64(canonical_json_bytes(claims))
    der = key.sign(
        f"{encoded_header}.{encoded_payload}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(der)
    s = min(s, P256_ORDER - s)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{encoded_header}.{encoded_payload}.{_b64(raw)}"


def signed_transfer_artifact(
    snapshot,
    *,
    scan_payload,
    device_id="DEVICE-01",
    source_host_id="HOST-01",
    site_id="SITE-01",
    authority_scope_id="PLANT-01",
    issued_at=None,
    expires_at=None,
    fence=1,
    lease_id="operation-lease-fixture-01",
    private_scalar=7,
    kid="lease-key-01",
):
    now = issued_at or datetime.now(timezone.utc)
    expiry = expires_at or now + timedelta(hours=1)
    source = snapshot["work_group_source"]
    group = snapshot["phs_work_group"]
    scanned = snapshot["phs_label_resolution"]["scanned_label"]
    claims = {
        "contract_version": LEASE_CONTRACT_VERSION,
        "lease_id": lease_id,
        "site_id": site_id,
        "program": "Container_Audit",
        "device_id": device_id,
        "source_host_id": source_host_id,
        "authority_scope_id": authority_scope_id,
        "ledger_plane": snapshot["ledger_plane"],
        "plane_epoch": snapshot["plane_epoch"],
        "operation": TRANSFER_OPERATION,
        "resource_id": f"phs-work-group:{group['group_id']}",
        "physical_label_id": scanned["label_id"],
        "physical_qr_sha256": physical_qr_sha256(scan_payload),
        "item_id": source["item_id"],
        "quantity": len(source["member_ids"]),
        "member_count": len(source["member_ids"]),
        "membership_hash": source["membership_hash"],
        "expected_versions": dict(snapshot["entity_versions"]),
        "issued_at": utc_text(now),
        "expires_at": utc_text(expiry),
        "fence": fence,
        "snapshot_hash": canonical_hash(snapshot),
    }
    key = ec.derive_private_key(private_scalar, ec.SECP256R1())
    jwk = _public_jwk(key)
    token = _sign(key, kid, claims)
    keyring = {
        "contract_version": KEYRING_CONTRACT_VERSION,
        "site_id": site_id,
        "current_kid": kid,
        "keys": [
            {
                "kid": kid,
                "status": "current",
                "public_jwk": jwk,
                "thumbprint": jwk_thumbprint(jwk),
            }
        ],
    }
    artifact = {
        "contract_version": ARTIFACT_CONTRACT_VERSION,
        "lease_id": lease_id,
        "status": "ACTIVE",
        "replayed": False,
        "token": token,
        "kid": kid,
        "expires_at": claims["expires_at"],
        "fence": fence,
        "snapshot_hash": claims["snapshot_hash"],
        "operation_snapshot": snapshot,
        "keyring": keyring,
    }
    return artifact, claims

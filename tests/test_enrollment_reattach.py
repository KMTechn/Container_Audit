from datetime import datetime, timedelta, timezone
import hashlib
from types import SimpleNamespace

import pytest

from tools import register_container_audit_worker_pc as registration
from vendor.kmtech_zero_pe import (
    P256KeyPair, PersistentPossessionKey, b64url_decode, canonical_json_bytes,
    jwk_thumbprint, verify_es256,
)


@pytest.fixture
def reattach_exchange(monkeypatch):
    # Ephemeral CNG signing exercises the product proof signer without changing
    # the operator's persistent Windows key store.
    pair = P256KeyPair.generate()
    fingerprint = jwk_thumbprint(pair.public_jwk)
    key = SimpleNamespace(
        descriptor=lambda: SimpleNamespace(fingerprint=fingerprint, public_jwk=pair.public_jwk),
        sign_es256=pair.sign_es256,
        assert_non_exportable=lambda: SimpleNamespace(private_export_status_hex="0x80090029"),
    )
    key.sign_reattach_proof = lambda proof: PersistentPossessionKey.sign_reattach_proof(key, proof)
    args = SimpleNamespace(enrollment_timeout_seconds=7)
    manifest = {"pc_identity": {"producer_install_id": "install-test", "source_host_id": "source-test"}}
    credential = {"producer_id": "producer-test", "endpoint_url": "https://worker.example.invalid/api/producer-ingest/v1/source-file"}
    calls = []
    changes = {"challenge": lambda value: None, "complete": lambda value: None, "status": 200,
        "key": key, "args": args, "manifest": manifest, "enroll_status": 409}

    def post(url, *, json, **kwargs):
        calls.append((url, json, kwargs))
        assert kwargs == {"headers": {"X-Producer-Enrollment-Token": "test-only"}, "timeout": 7, "allow_redirects": False, "verify": "isolated-ca.pem"}
        if url.endswith("/enroll"):
            return SimpleNamespace(status_code=changes["enroll_status"], json=lambda: {"error": {"code": "reattach_proof_required"}})
        if url.endswith("/challenge"):
            proof = {
                "contract_version": "producer-reattach-proof-v1",
                "challenge_id": "reattach-" + "a" * 32,
                "nonce": "n" * 43,
                "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "audience": "worker-analysis-producer-reattach-v1",
                **{field: json[field] for field in ("producer_id", "producer_install_id", "source_host_id", "manifest_hash")},
            }
            result = {"contract_version": "producer-reattach-challenge-v1", "proof_payload": proof, "possession_key_fingerprint": fingerprint}
            changes["challenge"](result)
        else:
            assert url.endswith("/v2/reattach")
            verify_es256(canonical_json_bytes(json["proof"]), b64url_decode(json["signature"], field="signature"), pair.public_jwk, require_low_s=True)
            result = {
                "contract_version": registration.REATTACH_COMPLETE_CONTRACT_VERSION,
                "status": "reattached", "identity_action": "REATTACHED",
                "authorization_state": "OPERATION_PENDING", "credential_epoch": 2,
                **credential, **manifest["pc_identity"],
                "key_id": "key-rotated-test", "active_manifest_hashes": [registration.manifest_hash(manifest)],
                "secret_fingerprint_sha256": hashlib.sha256(b"test-rotated-secret").hexdigest(),
            }
            result["client_receipt"] = {
                **result, "receipt_schema_version": "producer-self-enrollment-client-receipt-v1",
                "possession_key_fingerprint": fingerprint,
            }
            result["possession_key"] = {"contract_version": registration.POSSESSION_KEY_CONTRACT_VERSION, "fingerprint": fingerprint}
            result["secret"] = "test-rotated-secret"
            changes["complete"](result)
        return SimpleNamespace(status_code=changes["status"], json=lambda: result)

    monkeypatch.setattr(registration, "_post_enrollment_request", post)

    def run():
        return registration._possession_reattach(args, manifest, credential, key, headers={"X-Producer-Enrollment-Token": "test-only"}, verify="isolated-ca.pem")

    yield run, changes, calls, credential
    pair.close()


@pytest.mark.parametrize("epoch,state", [(2, "OPERATION_PENDING"), (4, "OPERATION_READY")])
def test_reattach_uses_existing_cng_proof_and_accepts_actual_server_epoch_contract(reattach_exchange, epoch, state):
    run, changes, calls, _ = reattach_exchange
    def rotate(result):
        result.update(credential_epoch=epoch, authorization_state=state)
        result["client_receipt"].update(credential_epoch=epoch, authorization_state=state)
    changes["complete"] = rotate
    result = run()
    assert result["credential_epoch"] == epoch
    assert len(calls) == 2


@pytest.mark.parametrize("field,value", [
    ("producer_id", "foreign"), ("producer_install_id", "foreign"),
    ("source_host_id", "foreign"), ("manifest_hash", "b" * 64),
    ("nonce", ""), ("nonce", "short"), ("challenge_id", "foreign"),
    ("expires_at", "2000-01-01T00:00:00Z"), ("expires_at", "2999-01-01T00:00:00Z"),
    ("expires_at", "bad"), ("audience", "foreign"), ("contract_version", "foreign"),
])
def test_reattach_rejects_invalid_challenge_before_signing_or_completion(reattach_exchange, field, value):
    run, changes, calls, _ = reattach_exchange
    changes["challenge"] = lambda payload: payload["proof_payload"].update({field: value})
    with pytest.raises(registration.DirectSyncPushError):
        run()
    assert len(calls) == 1


@pytest.mark.parametrize("field,value", [("contract_version", "foreign"), ("possession_key_fingerprint", "foreign")])
def test_reattach_rejects_foreign_challenge_envelope(reattach_exchange, field, value):
    run, changes, calls, _ = reattach_exchange
    changes["challenge"] = lambda payload: payload.update({field: value})
    with pytest.raises(registration.DirectSyncPushError):
        run()
    assert len(calls) == 1


@pytest.mark.parametrize("receipt,field,value", [
    (False, "producer_id", "foreign"), (False, "source_host_id", "foreign"),
    (False, "producer_install_id", "foreign"), (False, "endpoint_url", "https://foreign.invalid"),
    (False, "active_manifest_hashes", ["b" * 64]), (False, "identity_action", "CREATED"),
    (False, "credential_epoch", True), (False, "credential_epoch", 1),
    (False, "authorization_state", "unknown"), (False, "secret", "tampered"),
    (True, "credential_epoch", True), (True, "credential_epoch", 3),
    (True, "key_id", "foreign"), (True, "producer_id", "foreign"),
    (True, "endpoint_url", "https://foreign.invalid"),
    (True, "possession_key_fingerprint", "foreign"),
    (True, "secret_fingerprint_sha256", "b" * 64),
])
def test_reattach_rejects_inexact_result_before_local_finalization(reattach_exchange, receipt, field, value):
    run, changes, calls, _ = reattach_exchange
    changes["complete"] = lambda payload: (payload["client_receipt"] if receipt else payload).update({field: value})
    with pytest.raises(registration.DirectSyncPushError):
        run()
    assert len(calls) == 2


def test_reattach_refuses_redirect_and_insecure_origin(reattach_exchange):
    run, changes, calls, credential = reattach_exchange
    changes["status"] = 302
    with pytest.raises(registration.DirectSyncPushError):
        run()
    assert len(calls) == 1
    credential["endpoint_url"] = "http://worker.example.invalid/api/producer-ingest/v1/source-file"
    with pytest.raises(registration.DirectSyncPushError):
        run()
    assert len(calls) == 1


@pytest.mark.parametrize("status", [409, 403])
def test_self_enroll_continues_exact_reattach_refusal_and_finalizes_verified_result(reattach_exchange, monkeypatch, status):
    _, changes, calls, credential = reattach_exchange
    changes["enroll_status"] = status
    args = changes["args"]
    args.enrollment_token = "test-only"
    args.enrollment_token_env = ""
    args.enrollment_url = ""
    args.tls_ca_bundle_path = "isolated-ca.pem"
    class KeyContext:
        def __enter__(self): return changes["key"]
        def __exit__(self, *unused): pass
    monkeypatch.setattr(registration, "_initial_possession_key", lambda *args: KeyContext())
    finalized = []
    def finalize(*args, **kwargs):
        finalized.append(kwargs)
        return credential, kwargs["extra_report"]
    monkeypatch.setattr(registration, "_finalize_server_registration", finalize)
    selected = dict(credential, key_id="initial-key")
    if status == 403:
        with pytest.raises(registration.DirectSyncPushError):
            registration._self_enroll(args, changes["manifest"], selected, "dpapi", "test", {})
        assert len(calls) == 1 and not finalized
    else:
        _, report = registration._self_enroll(args, changes["manifest"], selected, "dpapi", "test", {})
        assert report["registration_action"] == "possession_reattach"
        assert len(calls) == 3 and len(finalized) == 1
        assert finalized[0]["registration_contract_version"] == registration.REATTACH_COMPLETE_CONTRACT_VERSION
        assert finalized[0]["response_payload"]["identity_action"] == "REATTACHED"

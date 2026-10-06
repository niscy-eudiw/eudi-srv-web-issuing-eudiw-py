"""Tests for credential issuance logic: proofs, key attestations, validity, JWE."""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwe, jwk

from app.services import credential_issuance as ci
from config_helpers import patch_configuration

CONFIG_ID = "eu.europa.ec.eudi.pid_mdoc"


def _p256_jwk():
    key = ec.generate_private_key(ec.SECP256R1())
    return key, json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))


def _proof_jwt(header_extra=None):
    key, public_jwk = _p256_jwk()
    return jwt.encode({"nonce": "n"}, key, algorithm="ES256", headers={"jwk": public_jwk, **(header_extra or {})}), key


@pytest.fixture
def metadata():
    configs = {
        CONFIG_ID: {
            "issuer_config": {"validity": 30},
            "credential_metadata": {
                "credential_reuse_policy": {"options": [{"details": ["once_only"], "batch_size": 2}]}
            },
        }
    }
    with patch.dict("app.services.credential_issuance.oidc_metadata", {"credential_configurations_supported": configs}, clear=True):
        yield configs


@pytest.fixture
def sessions():
    manager = MagicMock()
    manager.add_key_storage_status.return_value = 0
    with patch.object(ci, "session_manager", manager):
        yield manager


@pytest.fixture
def issue():
    with patch.object(ci, "issue_credentials_for_session", return_value={"credentials": []}) as mock:
        yield mock


@pytest.fixture
def config():
    with patch_configuration({"status_validator": {"enabled": False}, "service_url": "https://backend.test"}) as cfg:
        yield cfg


class TestHolderKeys:
    def test_pk_from_jwk_round_trip(self):
        key, public_jwk = _p256_jwk()
        pem = base64.urlsafe_b64decode(ci.pKfromJWK(public_jwk))
        loaded = serialization.load_pem_public_key(pem)
        assert loaded.public_numbers() == key.public_key().public_numbers()

    def test_pk_from_jwk_rejects_other_curves(self):
        key = ec.generate_private_key(ec.SECP384R1())
        public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        assert ci.pKfromJWK(public_jwk)["error"] == "invalid_proof"

    def test_pk_from_jwt_header(self):
        token, key = _proof_jwt()
        pem = base64.urlsafe_b64decode(ci.pKfromJWT(token))
        assert serialization.load_pem_public_key(pem).public_numbers() == key.public_key().public_numbers()

    def test_pk_from_jwt_without_jwk(self):
        token = jwt.encode({}, "secret", algorithm="HS256")
        with pytest.raises(KeyError):
            ci.pKfromJWT(token)


class TestValidity:
    def test_no_constraints(self):
        assert ci.compute_max_credential_exp(None, None) is None

    def test_ceiling_minus_one(self):
        ceiling = int(time.time()) + 1000
        assert ci.compute_max_credential_exp(ceiling + 50, ceiling) == ceiling - 1

    def test_past_ceiling_raises(self):
        with pytest.raises(ci.CredentialValidityError):
            ci.compute_max_credential_exp(int(time.time()) - 1, None)

    def test_custom_validity_within_ceiling(self):
        before = int(time.time())
        result = ci.compute_max_credential_exp(None, None, custom_validity_seconds=60)
        assert before + 60 <= result <= int(time.time()) + 60

    def test_custom_validity_capped_at_ceiling(self):
        ceiling = int(time.time()) + 100
        assert ci.compute_max_credential_exp(ceiling, None, custom_validity_seconds=10_000) == ceiling - 1

    def test_metadata_lookups(self, metadata):
        assert ci.get_batch_size(CONFIG_ID) == 2
        assert ci.get_custom_validity_seconds(CONFIG_ID) == 30 * 86400
        assert ci.get_batch_size("unknown") is None
        assert ci.get_custom_validity_seconds("unknown") is None


class TestGenerateCredentials:
    def test_single_jwt_proof(self, metadata, sessions, issue, config):
        token, _ = _proof_jwt()
        ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "jwt", "jwt": token}}, "s1")

        request = issue.call_args.args[1]
        assert request["credential_configuration_id"] == CONFIG_ID
        assert len(request["proofs"]) == 1 and "jwt" in request["proofs"][0]
        sessions.update_is_batch_credential.assert_not_called()
        # Custom validity (30 days) becomes the expiry ceiling.
        assert sessions.update_max_credential_exp.call_args.kwargs["max_credential_exp"] > time.time() + 29 * 86400

    def test_undecodable_single_jwt(self, metadata, sessions, issue, config):
        result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "jwt", "jwt": "garbage"}}, "s1")
        assert result == "" and not issue.called

    def test_batch_truncated_to_batch_size(self, metadata, sessions, issue, config):
        proofs = [_proof_jwt()[0] for _ in range(3)]
        ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proofs": {"jwt": proofs}}, "s1")

        assert len(issue.call_args.args[1]["proofs"]) == 2
        sessions.update_is_batch_credential.assert_called_once_with(session_id="s1", is_batch_credential=True)

    def test_invalid_jwt_in_batch_is_skipped(self, metadata, sessions, issue, config):
        ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proofs": {"jwt": ["not-a-jwt", _proof_jwt()[0]]}}, "s1")
        assert len(issue.call_args.args[1]["proofs"]) == 1

    def test_batch_jwt_without_jwk_is_invalid_proof(self, metadata, sessions, issue, config):
        token = jwt.encode({}, "secret", algorithm="HS256")
        result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proofs": {"jwt": [token]}}, "s1")
        assert result["error"] == "invalid_proof" and not issue.called

    def test_unsupported_proof_type(self, metadata, sessions, issue, config):
        result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proofs": {"cwt": ["x"]}}, "s1")
        assert result == {"error": "proof currently not supported"}

    def _attestation_claims(self, exp):
        _, key_a = _p256_jwk()
        _, key_b = _p256_jwk()
        return {
            "attested_keys": [key_a, key_b],
            "key_storage_status": {"exp": exp, "status": {"status_list": {"idx": 7, "uri": "u"}}},
        }

    @pytest.mark.parametrize("shape", ["proofs", "single", "jwt_header"])
    def test_key_attestation_registers_keys(self, metadata, sessions, issue, config, shape):
        exp = int(time.time()) + 3600
        if shape == "proofs":
            request = {"credential_configuration_id": CONFIG_ID, "proofs": {"attestation": ["ka.jwt"]}}
        elif shape == "single":
            request = {"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "attestation", "attestation": "ka.jwt"}}
        else:
            token, _ = _proof_jwt({"key_attestation": "ka.jwt"})
            request = {"credential_configuration_id": CONFIG_ID, "proofs": {"jwt": [token]}}

        with patch.object(ci, "decode_verify_attestation", return_value=self._attestation_claims(exp)) as verify:
            ci.generate_credentials(request, "s1")

        verify.assert_called_once_with("ka.jwt")
        sessions.add_key_storage_status.assert_called_once_with(session_id="s1", status={"status_list": {"idx": 7, "uri": "u"}})
        assert sessions.add_key_to_key_storage_status.call_count == 2
        assert [list(p) for p in issue.call_args.args[1]["proofs"]] == [["attestation"], ["attestation"]]
        # The KA expiry is the ceiling (validity 30 days would be later).
        assert sessions.update_max_credential_exp.call_args.kwargs["max_credential_exp"] == exp - 1

    @pytest.mark.parametrize("error", [ci.KARevokedError("revoked"), ci.KeyAttestationStatusError("unverifiable")])
    def test_rejected_key_attestation(self, metadata, sessions, issue, config, error):
        with patch.object(ci, "decode_verify_attestation", side_effect=error):
            result = ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proofs": {"attestation": ["ka"]}}, "s1")
        assert result == {"error": "invalid_proof", "error_description": str(error)}
        assert not issue.called

    def test_expired_wia_is_invalid_proof(self, metadata, sessions, issue, config):
        token, _ = _proof_jwt()
        result = ci.generate_credentials(
            {"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "jwt", "jwt": token}},
            "s1",
            wia_client_status={"exp": int(time.time()) - 10},
        )
        assert result["error"] == "invalid_proof" and not issue.called

    def test_unknown_proof_type_sends_no_proofs(self, metadata, sessions, issue, config):
        ci.generate_credentials({"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "cwt"}}, "s1")
        assert "proofs" not in issue.call_args.args[1]


class TestDecodeVerifyAttestation:
    def test_status_checked_when_validator_enabled(self):
        claims = {"key_storage_status": {"status": {"status_list": {"idx": 1, "uri": "u"}}}}
        cfg = {"status_validator": {"enabled": True, "url": "https://validator.test"}}
        with patch_configuration(cfg), patch.object(ci, "verify_jwt_with_x5c", return_value=claims), patch.object(
            ci, "check_status_list_revocation", return_value=False
        ) as check:
            assert ci.decode_verify_attestation("ka") == claims
        check.assert_called_once_with(url="https://validator.test", status_idx=1, status_uri="u")


class TestJwe:
    @pytest.fixture
    def encryption_key(self):
        key = jwk.JWK.generate(kty="EC", crv="P-256")
        with patch_configuration({"keys": {"credential_encryption_key": key.export_to_pem(private_key=True, password=None)}}):
            yield key

    def _encrypt(self, payload: bytes, key: jwk.JWK) -> str:
        token = jwe.JWE(payload, protected=json.dumps({"alg": "ECDH-ES", "enc": "A256GCM"}))
        token.add_recipient(key)
        return token.serialize(compact=True)

    def test_decrypt_round_trip(self, encryption_key):
        request = {"credential_configuration_id": CONFIG_ID, "proof": {"proof_type": "jwt", "jwt": "x"}}
        assert ci.decrypt_jwe_credential_request(self._encrypt(json.dumps(request).encode(), encryption_key)) == request

    def test_not_a_jwe(self, encryption_key):
        with pytest.raises(ValueError, match="expected 5 parts"):
            ci.decrypt_jwe_credential_request("a.b.c")

    def test_payload_not_json(self, encryption_key):
        with pytest.raises(ValueError, match="not valid JSON"):
            ci.decrypt_jwe_credential_request(self._encrypt(b"not json", encryption_key))

    def test_wrong_key(self, encryption_key):
        other = jwk.JWK.generate(kty="EC", crv="P-256")
        with pytest.raises(ValueError, match="Failed to decrypt JWE"):
            ci.decrypt_jwe_credential_request(self._encrypt(b"{}", other))

    def test_encrypt_jwe_drops_none_header_values(self):
        key = jwk.JWK.generate(kty="EC", crv="P-256")
        token = ci.encrypt_jwe({"a": 1}, key, alg="ECDH-ES", enc="A128GCM", kid=None, typ="x")
        parsed = jwe.JWE()
        parsed.deserialize(token, key=key)
        header = json.loads(parsed.objects["protected"])
        assert {k: header[k] for k in ("alg", "enc", "typ")} == {"alg": "ECDH-ES", "enc": "A128GCM", "typ": "x"}
        assert "kid" not in header and "epk" in header  # ECDH-ES ephemeral key
        assert json.loads(parsed.payload) == {"a": 1}

"""Tests for JWT proofs whose holder key is a kid DID URL (OpenID4VCI 1.0 appendix F.1, #86)."""

import base64
import json
import time
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.services import credential_issuance as ci
from app.utils.did import jwk_from_did_url
from proof_helpers import c_nonce, p256_jwk, proof_jwt
from test_credential_issuance import CONFIG_ID, _request, _single, config, issue, metadata, sessions  # noqa: F401

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def did_key(key: ec.EllipticCurvePrivateKey, prefix: bytes = b"\x80\x24", compressed: bool = True) -> str:
    point_format = serialization.PublicFormat.CompressedPoint if compressed else serialization.PublicFormat.UncompressedPoint
    point = key.public_key().public_bytes(serialization.Encoding.X962, point_format)
    return "did:key:z" + _b58encode(prefix + point)


def did_jwk(public_jwk: dict) -> str:
    return "did:jwk:" + base64.urlsafe_b64encode(json.dumps(public_jwk).encode()).rstrip(b"=").decode()


def _holder_numbers(issue):
    [holder] = issue.call_args.args[1]["proofs"]
    return serialization.load_pem_public_key(base64.urlsafe_b64decode(holder["jwt"])).public_numbers()


class TestJwkFromDidUrl:
    def test_did_key_round_trip(self):
        key = ec.generate_private_key(ec.SECP256R1())
        resolved = jwk_from_did_url(did_key(key))
        numbers = key.public_key().public_numbers()
        assert resolved["crv"] == "P-256" and resolved["kty"] == "EC"
        assert int.from_bytes(base64.urlsafe_b64decode(resolved["x"] + "="), "big") == numbers.x
        assert int.from_bytes(base64.urlsafe_b64decode(resolved["y"] + "="), "big") == numbers.y

    def test_did_key_fragment_must_be_the_key(self):
        did = did_key(ec.generate_private_key(ec.SECP256R1()))
        assert jwk_from_did_url(f"{did}#{did[len('did:key:'):]}")
        with pytest.raises(ValueError):
            jwk_from_did_url(f"{did}#other")

    def test_did_jwk_round_trip_and_fragment(self):
        _, public_jwk = p256_jwk()
        assert jwk_from_did_url(did_jwk(public_jwk) + "#0") == public_jwk
        with pytest.raises(ValueError):
            jwk_from_did_url(did_jwk(public_jwk) + "#1")

    @pytest.mark.parametrize(
        "kid",
        [
            None,
            "0",
            "https://example.com/key",
            "did:web:example.com#key-1",
            "did:key:",
            "did:key:zInvalid0OIl",
            "did:jwk:!!!",
            "did:jwk:" + base64.urlsafe_b64encode(b"[1]").decode(),
            "x" * 5000,
        ],
    )
    def test_rejects_unsupported_or_malformed(self, kid):
        with pytest.raises(ValueError):
            jwk_from_did_url(kid)

    def test_rejects_other_multicodec(self):
        # 0xed01: Ed25519 public key
        with pytest.raises(ValueError, match="P-256"):
            jwk_from_did_url("did:key:z" + _b58encode(b"\xed\x01" + bytes(32)))

    def test_rejects_uncompressed_did_key(self):
        with pytest.raises(ValueError, match="compressed"):
            jwk_from_did_url(did_key(ec.generate_private_key(ec.SECP256R1()), compressed=False))

    def test_rejects_did_jwk_with_private_key(self):
        key, public_jwk = p256_jwk()
        private = {**public_jwk, "d": "AAAA"}
        with pytest.raises(ValueError, match="private"):
            jwk_from_did_url(did_jwk(private))


@pytest.mark.usefixtures("sessions", "config")
class TestKidProofs:
    @pytest.mark.parametrize("shape", ["proofs", "single"])
    @pytest.mark.parametrize("method", ["did:key", "did:jwk"])
    def test_kid_proof_binds_did_key(self, metadata, sessions, issue, config, shape, method):
        key, public_jwk = p256_jwk()
        kid = did_key(key) if method == "did:key" else did_jwk(public_jwk) + "#0"
        token, _ = proof_jwt(key, include_jwk=False, header_extra={"kid": kid})

        ci.generate_credentials(_request([token]) if shape == "proofs" else _single(token), "s1")

        assert _holder_numbers(issue) == key.public_key().public_numbers()

    def test_kid_proof_signed_by_another_key_is_rejected(self, metadata, sessions, issue, config):
        holder = ec.generate_private_key(ec.SECP256R1())
        token, _ = proof_jwt(include_jwk=False, header_extra={"kid": did_key(holder)})  # signed by a fresh key

        result = ci.generate_credentials(_request([token]), "s1")

        assert result == {"error": "invalid_proof", "error_description": "Proof JWT signature is not valid"}
        assert not issue.called

    @pytest.mark.parametrize("extra", [{"x5c": ["MIIB"]}, {}])
    def test_kid_is_exclusive_with_jwk_and_x5c(self, metadata, sessions, issue, config, extra):
        key = ec.generate_private_key(ec.SECP256R1())
        include_jwk = not extra
        token, _ = proof_jwt(key, include_jwk=include_jwk, header_extra={"kid": did_key(key), **extra})

        result = ci.generate_credentials(_request([token]), "s1")

        assert result["error"] == "invalid_proof" and "must not combine" in result["error_description"]
        assert not issue.called

    def test_unsupported_did_method_is_invalid_proof(self, metadata, sessions, issue, config):
        token, _ = proof_jwt(include_jwk=False, header_extra={"kid": "did:web:example.com#key-1"})

        result = ci.generate_credentials(_request([token]), "s1")

        assert result["error"] == "invalid_proof" and not issue.called

    def test_kid_with_key_attestation_references_attested_key(self, metadata, sessions, issue, config):
        # The OpenID4VCI 1.0 appendix F.1 example: {"kid": "0", "key_attestation": ...}
        attested_key, attested_jwk = p256_jwk()
        _, other_jwk = p256_jwk()
        claims = {
            "attested_keys": [attested_jwk, other_jwk],
            "key_storage_status": {"exp": int(time.time()) + 3600, "status": {"status_list": {"idx": 1, "uri": "u"}}},
            "nonce": c_nonce(),
        }
        token, _ = proof_jwt(attested_key, include_jwk=False, header_extra={"kid": "0", "key_attestation": "ka.jwt"})

        with patch.object(ci, "decode_verify_attestation", return_value=claims):
            result = ci.generate_credentials(_request([token]), "s1")

        assert "error" not in result
        assert len(issue.call_args.args[1]["proofs"]) == 2

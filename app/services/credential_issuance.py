# coding: latin-1
###############################################################################
# Copyright (c) 2025 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""Credential endpoint business logic (OpenID4VCI).

Turns a validated credential request into a call to the credential
formatters: extracts holder keys from the proofs, verifies key attestations
(and their revocation status), caps the batch size and computes the expiry
ceiling imposed by the wallet / key attestations (TS3 2.2.2.1, 2.4.3).
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwe, jwk

from app.core.config import CONFIGURATION
from app.core.log_utils import safe
from app.core.state import oidc_metadata, session_manager
from app.services.auth_server import StatusCheckError, check_status_list_revocation
from app.services.dynamic_formatter import issue_credentials_for_session
from app.services.trust import KEY_ATTESTATION_CONTEXT, trust_context, trust_use_case, verify_jwt_with_x5c
from app.utils.encoding import b64url_decode

logger = logging.getLogger(__name__)

DEFERRED_ONLY_CONFIGURATION = "eu.europa.ec.eudi.pid_mdoc_deferred"
NONCE_LIFETIME_SECONDS = 3600


#: OpenID4VCI JWT proof type header and accepted algorithms (holder keys are P-256).
PROOF_JWT_TYP = "openid4vci-proof+jwt"
PROOF_ALGORITHMS = ("ES256",)
#: Accepted clock skew for ``iat`` and maximum proof age.
PROOF_IAT_LEEWAY_SECONDS = 60
PROOF_MAX_AGE_SECONDS = 3600


class InvalidProofError(Exception):
    """Raised when a proof (JWT or key attestation) is not acceptable."""


class CredentialValidityError(Exception):
    """Raised when the WIA / KA validity ceiling has already passed."""


class KeyAttestationStatusError(Exception):
    """Raised when a key attestation's status rules it out (revoked or unverifiable)."""


class KARevokedError(KeyAttestationStatusError):
    """Raised when a key attestation is revoked."""


# ---------------------------------------------------------------------------
# Holder keys
# ---------------------------------------------------------------------------


def pKfromJWK(jwk_dict: Dict[str, Any]) -> Any:
    """Converts a P-256 JWK into the base64url PEM device key format.

    Args:
        jwk_dict: Public JWK.

    Returns:
        Base64url encoded PEM ``SubjectPublicKeyInfo``, or an
        ``invalid_proof`` error dict when the curve is not P-256.
    """
    if jwk_dict.get("crv") != "P-256":
        return {
            "error": "invalid_proof",
            "error_description": "Credential Issuer only supports P-256 curves",
        }

    public_key = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(b64url_decode(jwk_dict["x"]), "big"),
        y=int.from_bytes(b64url_decode(jwk_dict["y"]), "big"),
        curve=ec.SECP256R1(),
    ).public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.urlsafe_b64encode(public_key_pem).decode("utf-8")


def _proof_audiences(session_id: str) -> List[str]:
    """Returns the credential issuer identifiers a proof may be addressed to.

    Args:
        session_id: Issuance session.

    Returns:
        The URL of the session's frontend when known, otherwise the URLs of
        all configured frontends (each with and without a trailing slash).
    """
    frontends = (CONFIGURATION.get("frontend") or {}).get("frontends_config") or {}
    current = session_manager.get_session(session_id=session_id)
    frontend_id = getattr(current, "frontend_id", None) if current else None
    if frontend_id in frontends:
        urls = [frontends[frontend_id]["url"]]
    else:
        urls = [cfg["url"] for cfg in frontends.values() if cfg.get("url")]
    return [variant for url in urls for variant in (url.rstrip("/"), url.rstrip("/") + "/")]


def _nonce_required() -> bool:
    """Tells whether proofs must carry a valid ``c_nonce``.

    Returns:
        ``proof_validation.require_nonce`` from the configuration (default ``True``).
    """
    return bool((CONFIGURATION.get("proof_validation") or {}).get("require_nonce", True))


def verify_c_nonce(c_nonce: Any) -> Dict[str, Any]:
    """Checks that a ``c_nonce`` was issued by :func:`create_c_nonce` and is still valid.

    The nonce is a JWE only this issuer can decrypt, so no server-side
    nonce store is needed.

    Args:
        c_nonce: Nonce from a proof.

    Returns:
        The nonce claims.

    Raises:
        InvalidProofError: If the nonce is missing, cannot be decrypted, was
            not issued for this credential endpoint or has expired.
    """
    if not isinstance(c_nonce, str) or not c_nonce:
        raise InvalidProofError("Proof has no c_nonce")
    try:
        token = jwe.JWE()
        token.deserialize(c_nonce, key=jwk.JWK.from_pem(CONFIGURATION["keys"]["nonce_key"]))
        claims = json.loads(token.payload)
    except Exception as e:
        raise InvalidProofError("c_nonce is not valid") from e

    service_url = CONFIGURATION["service_url"]
    if claims.get("iss") != service_url or f"{service_url}/credential" not in (claims.get("aud") or []):
        raise InvalidProofError("c_nonce was not issued for this credential endpoint")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < time.time():
        raise InvalidProofError("c_nonce has expired")
    return claims


def _public_key_from_jwk(jwk_dict: Any) -> Any:
    """Loads a public JWK as a PyJWT verification key.

    Args:
        jwk_dict: JWK from a proof header or a key attestation.

    Returns:
        The public key.

    Raises:
        InvalidProofError: If the JWK is missing, private or unusable.
    """
    if not isinstance(jwk_dict, dict):
        raise InvalidProofError("Proof has no usable jwk")
    if "d" in jwk_dict:
        raise InvalidProofError("Proof jwk must not contain private key material")
    try:
        return jwt.PyJWK(jwk_dict).key
    except Exception as e:
        raise InvalidProofError("Proof jwk is not a valid public key") from e


def verify_proof_jwt(
    proof_jwt: str, session_id: str, signing_jwks: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Verifies an OpenID4VCI JWT proof of possession.

    Checks ``typ`` (``openid4vci-proof+jwt``), ``alg``, the signature (with
    the ``jwk`` header, or one of ``signing_jwks`` for proofs backed by a key
    attestation), ``aud`` (the credential issuer identifier), ``iat``
    freshness and, unless disabled, the ``nonce`` (a valid ``c_nonce``).

    Args:
        proof_jwt: Compact proof JWT.
        session_id: Issuance session (selects the expected ``aud``).
        signing_jwks: Keys allowed to sign the proof instead of the ``jwk``
            header (the attested keys of a key attestation).

    Returns:
        The verified proof claims.

    Raises:
        InvalidProofError: If any check fails.
    """
    try:
        # The proof carries its own key (jwk header): typ / alg / key are read
        # first, then the signature is verified with that key below.
        header = jwt.get_unverified_header(proof_jwt)  # NOSONAR
    except jwt.DecodeError as e:
        raise InvalidProofError("Proof JWT is malformed") from e

    if header.get("typ") != PROOF_JWT_TYP:
        raise InvalidProofError(f"Proof JWT typ must be {PROOF_JWT_TYP}")
    alg = header.get("alg")
    if alg not in PROOF_ALGORITHMS:
        raise InvalidProofError("Proof JWT alg is not supported")

    candidates = signing_jwks if signing_jwks is not None else [header.get("jwk")]
    audiences = _proof_audiences(session_id)
    claims: Optional[Dict[str, Any]] = None
    for candidate in candidates:
        try:
            claims = jwt.decode(
                proof_jwt,
                key=_public_key_from_jwk(candidate),
                algorithms=[alg],
                audience=audiences,
                options={"require": ["aud", "iat"]},
                leeway=PROOF_IAT_LEEWAY_SECONDS,
            )
            break
        except jwt.InvalidSignatureError:
            continue
        except jwt.InvalidTokenError as e:
            raise InvalidProofError(f"Proof JWT is not valid: {e}") from e
    if claims is None:
        raise InvalidProofError("Proof JWT signature is not valid")

    if claims["iat"] < time.time() - PROOF_MAX_AGE_SECONDS:
        raise InvalidProofError("Proof JWT is too old")
    if _nonce_required():
        verify_c_nonce(claims.get("nonce"))

    logger.debug(f", Session ID: {session_id}, Proof JWT verified (aud={safe(claims.get('aud'), 100)})")
    return claims


def _holder_key(jwk_dict: Dict[str, Any]) -> str:
    """Converts a verified P-256 JWK to the device key format.

    Args:
        jwk_dict: Public JWK.

    Returns:
        Base64url encoded PEM public key.

    Raises:
        InvalidProofError: If the key is not on P-256.
    """
    device_key = pKfromJWK(jwk_dict)
    if not isinstance(device_key, str):
        raise InvalidProofError("Credential Issuer only supports P-256 holder keys")
    return device_key


# ---------------------------------------------------------------------------
# Key attestations
# ---------------------------------------------------------------------------


def decode_verify_attestation(jwt_raw: str) -> Dict[str, Any]:
    """Verifies a key attestation JWT and checks its revocation status.

    Args:
        jwt_raw: Key attestation JWT.

    Returns:
        The attestation claims.

    The signing chain is trusted via the trust validator (when enabled) or
    the local trusted CAs; see :func:`app.services.trust.verify_x5c_chain`.

    Raises:
        KARevokedError: If the attestation's status list entry is revoked.
        KeyAttestationStatusError: If its status cannot be verified.
        ValueError, CertificateVerificationError, jwt.InvalidTokenError:
            If verification fails.
    """
    claims = verify_jwt_with_x5c(
        jwt_raw=jwt_raw,
        verification_context=trust_context("key_attestation", KEY_ATTESTATION_CONTEXT),
        use_case=trust_use_case("key_attestation"),
    )

    key_storage_status = claims.get("key_storage_status")
    if key_storage_status and CONFIGURATION["status_validator"]["enabled"]:
        status_list = key_storage_status["status"]["status_list"]
        try:
            revoked = check_status_list_revocation(
                url=CONFIGURATION["status_validator"]["url"],
                status_idx=status_list["idx"],
                status_uri=status_list["uri"],
            )
        except StatusCheckError as e:
            # Fail closed: an attestation whose status cannot be checked is not accepted.
            raise KeyAttestationStatusError(f"Key Attestation status could not be verified: {e}") from e
        if revoked:
            raise KARevokedError("Key Attestation is revoked")
    return claims


def _register_attested_keys(
    claims: Dict[str, Any], session_id: str, pub_keys: List[Dict[str, Any]], ka_exps: List[int]
) -> None:
    """Records a verified key attestation and its attested keys.

    The KA status is appended to the session's client status, each attested
    key is added under it and to ``pub_keys``, and the KA expiry is
    collected into ``ka_exps``.

    Args:
        claims: Verified attestation claims.
        session_id: Issuance session.
        pub_keys: Holder keys collected so far (mutated).
        ka_exps: KA ``key_storage_status.exp`` values (mutated).
    """
    key_storage_status = claims.get("key_storage_status")
    if key_storage_status and key_storage_status.get("exp") is not None:
        ka_exps.append(key_storage_status["exp"])

    ka_index = session_manager.add_key_storage_status(
        session_id=session_id,
        status=key_storage_status.get("status") if key_storage_status else None,
    )

    for attested_jwk in claims["attested_keys"]:
        device_key = _holder_key(attested_jwk)
        pub_keys.append({"attestation": device_key})
        if ka_index is not None:
            session_manager.add_key_to_key_storage_status(
                session_id=session_id, key_storage_status_index=ka_index, key=device_key
            )


def _verified_attestation(attestation: str, session_id: str, origin: str, require_nonce: bool) -> Dict[str, Any]:
    """Verifies a key attestation (signature, trust, revocation, optionally nonce).

    Args:
        attestation: Key attestation JWT.
        session_id: Issuance session.
        origin: Where the attestation came from (for logging).
        require_nonce: Whether the attestation must carry a valid ``c_nonce``
            (when used directly as the proof).

    Returns:
        The attestation claims.

    Raises:
        InvalidProofError: If the attestation is revoked, unverifiable or
            lacks a valid nonce.
    """
    try:
        claims = decode_verify_attestation(attestation)
    except KeyAttestationStatusError as e:
        logger.warning(f", Session ID: {session_id}, Key attestation rejected ({origin}): {safe(e)}")
        raise InvalidProofError(str(e)) from e
    if not isinstance(claims.get("attested_keys"), list) or not claims["attested_keys"]:
        raise InvalidProofError("Key attestation has no attested_keys")
    if require_nonce and _nonce_required():
        verify_c_nonce(claims.get("nonce"))
    return claims


# ---------------------------------------------------------------------------
# Batch size / validity
# ---------------------------------------------------------------------------


def _credential_config(credential_configuration_id: str) -> Dict[str, Any]:
    """Returns a credential configuration, or ``{}`` if unknown.

    Args:
        credential_configuration_id: Configuration id.

    Returns:
        The configuration.
    """
    return oidc_metadata["credential_configurations_supported"].get(credential_configuration_id, {})


def get_batch_size(credential_configuration_id: str) -> Optional[int]:
    """Returns the ``batch_size`` of the configuration's ``once_only`` reuse policy.

    Args:
        credential_configuration_id: Configuration id.

    Returns:
        The batch size, or ``None`` when not configured.
    """
    options = (
        _credential_config(credential_configuration_id)
        .get("credential_metadata", {})
        .get("credential_reuse_policy", {})
        .get("options", [])
    )
    return next((o.get("batch_size") for o in options if "once_only" in o.get("details", [])), None)


def get_custom_validity_seconds(credential_configuration_id: str) -> Optional[int]:
    """Returns the configured credential validity in seconds.

    Args:
        credential_configuration_id: Configuration id.

    Returns:
        ``issuer_config.validity`` (days) converted to seconds, or ``None``.
    """
    validity_days = _credential_config(credential_configuration_id).get("issuer_config", {}).get("validity")
    return validity_days * 24 * 60 * 60 if validity_days is not None else None


def compute_max_credential_exp(
    wia_client_status_exp: Optional[int],
    ka_key_storage_status_exp: Optional[int],
    custom_validity_seconds: Optional[int] = None,
) -> Optional[int]:
    """Computes the latest allowed credential expiry.

    TS3 2.4.3: the technical validity of a PID SHALL end before
    ``client_status.exp`` (WIA) and ``key_storage_status.exp`` (KA). When a
    custom validity is configured it is used, capped by that ceiling.

    Args:
        wia_client_status_exp: WIA expiry (epoch seconds).
        ka_key_storage_status_exp: Earliest KA expiry (epoch seconds).
        custom_validity_seconds: Configured credential lifetime.

    Returns:
        The maximum expiry (epoch seconds), or ``None`` for no constraint.

    Raises:
        CredentialValidityError: If the ceiling is already in the past.
    """
    now = int(time.time())
    candidates = [c for c in (wia_client_status_exp, ka_key_storage_status_exp) if c is not None]
    hard_ceiling = min(candidates) if candidates else None

    if hard_ceiling is not None and hard_ceiling <= now:
        raise CredentialValidityError(
            "WIA/KA revocation maintenance period has already expired or expires immediately"
        )

    if custom_validity_seconds is not None:
        proposed = now + custom_validity_seconds
        if hard_ceiling is not None and proposed >= hard_ceiling:
            proposed = hard_ceiling - 1
        return proposed

    return hard_ceiling - 1 if hard_ceiling is not None else None


# ---------------------------------------------------------------------------
# Credential generation
# ---------------------------------------------------------------------------


def _collect_jwt_proof(
    proof_jwt: str, session_id: str, pub_keys: List[Dict[str, Any]], ka_exps: List[int]
) -> None:
    """Verifies one JWT proof and records the holder key(s) it proves.

    A proof with a ``key_attestation`` header must be signed by one of the
    attested keys; all attested keys are then issued to. Otherwise the proof
    is signed by its ``jwk`` header key, which becomes the holder key.

    Args:
        proof_jwt: Compact proof JWT.
        session_id: Issuance session.
        pub_keys: Holder keys (mutated).
        ka_exps: KA expiry values (mutated).

    Raises:
        InvalidProofError: If the proof or its key attestation is invalid.
    """
    try:
        # Only selects the key source (key_attestation or jwk); verify_proof_jwt
        # verifies the signature before any key is used.
        header = jwt.get_unverified_header(proof_jwt)  # NOSONAR
    except jwt.DecodeError as e:
        raise InvalidProofError("Proof JWT is malformed") from e

    if "key_attestation" in header:
        claims = _verified_attestation(header["key_attestation"], session_id, "jwt proof header", require_nonce=False)
        verify_proof_jwt(proof_jwt, session_id, signing_jwks=claims["attested_keys"])
        _register_attested_keys(claims, session_id, pub_keys, ka_exps)
        return

    verify_proof_jwt(proof_jwt, session_id)
    pub_keys.append({"jwt": _holder_key(header["jwk"])})


def _collect_proof_keys(
    credential_request: Dict[str, Any],
    session_id: str,
    pub_keys: List[Dict[str, Any]],
    ka_exps: List[int],
) -> None:
    """Verifies the request's proof(s) and collects the proven holder keys.

    Args:
        credential_request: Validated credential request.
        session_id: Issuance session.
        pub_keys: Holder keys (mutated).
        ka_exps: KA expiry values (mutated).

    Raises:
        InvalidProofError: If any proof is invalid or of an unsupported type.
    """
    proof = credential_request.get("proof")

    if proof is not None and "proofs" not in credential_request:
        match proof.get("proof_type"):
            case "jwt":
                _collect_jwt_proof(proof["jwt"], session_id, pub_keys, ka_exps)
            case "attestation":
                claims = _verified_attestation(proof["attestation"], session_id, "single attestation proof", True)
                _register_attested_keys(claims, session_id, pub_keys, ka_exps)
            case _:
                raise InvalidProofError("Unsupported proof type")
        return

    for proof_type, proof_values in (credential_request.get("proofs") or {}).items():
        if not isinstance(proof_values, list) or not proof_values:
            raise InvalidProofError(f"proofs.{safe(proof_type, 30)} must be a non-empty list")
        match proof_type:
            case "jwt":
                for proof_jwt in proof_values:
                    _collect_jwt_proof(proof_jwt, session_id, pub_keys, ka_exps)
            case "attestation":
                for attestation in proof_values:
                    claims = _verified_attestation(attestation, session_id, "attestation proof", True)
                    _register_attested_keys(claims, session_id, pub_keys, ka_exps)
            case _:
                raise InvalidProofError("Unsupported proof type")

    # TS3 2.2.2.1: cap keys used against the issuer's configured batch_size.
    batch_size = get_batch_size(credential_request["credential_configuration_id"])
    if batch_size and len(pub_keys) > batch_size:
        logger.info(
            f", Session ID: {session_id}, Proofs contained {len(pub_keys)} keys, truncating to batch_size {batch_size}"
        )
        del pub_keys[batch_size:]


def generate_credentials(
    credential_request: Dict[str, Any], session_id: str, wia_client_status: Optional[Dict[str, Any]] = None
) -> Any:
    """Issues the credential(s) for a validated credential request.

    Every proof is verified (:func:`verify_proof_jwt` / key attestations)
    and the proven holder keys are collected; the expiry ceiling is stored
    in the session, and the credentials are formatted and signed with the
    session's user data
    (:func:`app.services.dynamic_formatter.issue_credentials_for_session`).

    Args:
        credential_request: Validated credential request.
        session_id: Issuance session.
        wia_client_status: ``client_status`` claim of the access token.

    Returns:
        ``{"credentials": [...]}`` or an error dict: ``invalid_proof`` when a
        proof is missing / invalid (signature, ``typ``, ``aud``, ``iat``,
        ``c_nonce``, key attestation), ``credential_request_denied`` when
        signing fails.
    """
    configuration_id = credential_request["credential_configuration_id"]
    pub_keys: List[Dict[str, Any]] = []
    ka_exps: List[int] = []

    try:
        _collect_proof_keys(credential_request, session_id, pub_keys, ka_exps)
    except InvalidProofError as e:
        logger.warning(f", Session ID: {session_id}, Invalid proof: {safe(e)}")
        return {"error": "invalid_proof", "error_description": str(e)}
    if not pub_keys:
        logger.warning(f", Session ID: {session_id}, Invalid proof: no holder key proven")
        return {"error": "invalid_proof", "error_description": "No valid proof"}

    formatter_request: Dict[str, Any] = {"credential_configuration_id": configuration_id, "proofs": pub_keys}

    if len(pub_keys) > 1:
        session_manager.update_is_batch_credential(session_id=session_id, is_batch_credential=True)

    # TS3 2.4.3: credential validity SHALL end before client_status.exp (WIA)
    # and key_storage_status.exp (KA).
    try:
        max_exp = compute_max_credential_exp(
            wia_client_status_exp=wia_client_status.get("exp") if wia_client_status else None,
            ka_key_storage_status_exp=min(ka_exps) if ka_exps else None,
            custom_validity_seconds=get_custom_validity_seconds(configuration_id),
        )
    except CredentialValidityError as e:
        logger.error(f", Session ID: {session_id}, {safe(e)}")
        return {"error": "invalid_proof", "error_description": str(e)}

    logger.debug(
        f", Session ID: {session_id}, {len(pub_keys)} holder key(s) from proofs, "
        f"{len(ka_exps)} key attestation expiry value(s), max credential exp={max_exp}"
    )
    if max_exp is not None:
        session_manager.update_max_credential_exp(session_id=session_id, max_credential_exp=max_exp)

    try:
        return issue_credentials_for_session(session_id, formatter_request)
    except Exception:
        logger.exception(f", Session ID: {session_id}, credential creation failed")
        return {"error": "credential_request_denied", "error_description": "The credential could not be issued"}


# ---------------------------------------------------------------------------
# Encryption / nonces
# ---------------------------------------------------------------------------


def decrypt_jwe_credential_request(jwt_token: str) -> Dict[str, Any]:
    """Decrypts a JWE credential request with the issuer encryption key.

    Args:
        jwt_token: Compact JWE (5 parts).

    Returns:
        The decrypted credential request.

    Raises:
        ValueError: If the token is not a JWE, cannot be decrypted, or the
            payload is not JSON.
    """
    if jwt_token.count(".") != 4:
        raise ValueError("Invalid JWE format - expected 5 parts")

    try:
        private_key = jwk.JWK.from_pem(CONFIGURATION["keys"]["credential_encryption_key"])
        jwe_token = jwe.JWE()
        jwe_token.deserialize(jwt_token)
        jwe_token.decrypt(private_key)
        payload = jwe_token.payload.decode("utf-8")
        logger.debug("Decrypted JWE credential request")
        return json.loads(payload)
    except FileNotFoundError as e:
        logger.error("Private key file not found")
        raise ValueError("Private key file not found") from e
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse decrypted payload as JSON: {safe(str(e))}")
        raise ValueError(f"Decrypted payload is not valid JSON: {str(e)}") from e
    except Exception as e:
        logger.error(f"Failed to decrypt JWE: {safe(str(e))}")
        raise ValueError(f"Failed to decrypt JWE: {str(e)}") from e


def encrypt_jwe(payload: Dict[str, Any], key: jwk.JWK, alg: str, enc: str, **header: Any) -> str:
    """Encrypts a JSON payload as a compact JWE.

    Args:
        payload: JSON-serializable payload.
        key: Recipient key (public, or private whose public part is used).
        alg: Key management algorithm (e.g. ``ECDH-ES``, ``RSA-OAEP``).
        enc: Content encryption algorithm (e.g. ``A256GCM``).
        **header: Extra protected header parameters (e.g. ``kid``, ``typ``).

    Returns:
        The compact serialization.

    Raises:
        jwcrypto.common.JWException: If the key / algorithms are unusable.
    """
    protected = {"alg": alg, "enc": enc, **{k: v for k, v in header.items() if v is not None}}
    token = jwe.JWE(json.dumps(payload).encode("utf-8"), protected=json.dumps(protected))
    token.add_recipient(key)
    return token.serialize(compact=True)


def create_c_nonce() -> str:
    """Creates an encrypted ``c_nonce`` JWT bound to the credential endpoint.

    The payload is encrypted to the issuer's own ``nonce_key`` (RSA-OAEP,
    A256GCM), so only the issuer can read it back.

    Returns:
        The compact JWE.
    """
    service_url = CONFIGURATION["service_url"]
    now = int(time.time())
    payload = {
        "iss": service_url,
        "iat": now,
        "exp": now + NONCE_LIFETIME_SECONDS,
        "source_endpoint": f"{service_url}/nonce",
        "aud": [f"{service_url}/credential"],
    }
    nonce_key = jwk.JWK.from_pem(CONFIGURATION["keys"]["nonce_key"])
    return encrypt_jwe(payload, nonce_key, alg="RSA-OAEP", enc="A256GCM", typ="cnonce+jwt")

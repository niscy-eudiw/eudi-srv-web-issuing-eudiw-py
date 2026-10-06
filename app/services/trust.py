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
"""Verification of JWTs signed with an ``x5c`` certificate chain.

Key attestations, wallet attestations and signed requests carry their signing
certificate chain in the JOSE ``x5c`` header. :func:`verify_x5c_chain`
establishes trust in that chain and the JWT signature is then verified with
the leaf certificate's public key.

Trust policy:
    * If ``trust_validator.enabled`` is true, the external trust validator is
      asked first. When it confirms the chain, the chain is trusted.
    * If the validator rejects the chain, errors, or is not configured /
      disabled, the chain is checked against the local trusted CA folder
      (``trusted_CAs_path``, loaded into :data:`app.core.state.trusted_CAs`).
    * Otherwise :class:`CertificateVerificationError` is raised.

Trust validator API (``eudi-srv-trust-validator``, ``POST /trust``):
    request ``{"chain": [...], "verificationContext": ..., "useCase": ...}``;
    ``200`` answers ``{"trusted", "trustAnchor", "error"}``, ``400`` / ``500``
    answer ``{"description"}``. ``useCase`` is only needed for the ``Custom``
    context.

Attributes:
    VERIFICATION_CONTEXTS: Contexts accepted by the trust validator.
    KEY_ATTESTATION_CONTEXT: Default context for key attestations (signed by
        the wallet provider). Override with
        ``trust_validator.contexts.key_attestation``.
    CREDENTIAL_OFFER_REQUEST_CONTEXT: Default context for the signed
        ``/credentialOfferReq2`` request
        (``trust_validator.contexts.credential_offer_request``).
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from sd_jwt.holder import SDJWTHolder

from app.core.config import CONFIGURATION
from app.core.log_utils import safe
from app.core.errors import CertificateVerificationError
from app.core.state import trusted_CAs
from app.utils.crypto import certificate_validity
from app.utils.encoding import b64_decode_x5c, b64url_decode

logger = logging.getLogger(__name__)

#: Key types PyJWT can verify signatures with.
SUPPORTED_PUBLIC_KEY_TYPES = (
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
)

VERIFICATION_CONTEXTS = frozenset(
    {
        "WalletProviderAttestation",
        "WalletOrKeyStorageStatus",
        "PID",
        "PIDStatus",
        "PubEAA",
        "PubEAAStatus",
        "QEAA",
        "QEAAStatus",
        "EAA",
        "EAAStatus",
        "WalletRelyingPartyRegistrationCertificate",
        "WalletRelyingPartyRegistrationCertificateStatus",
        "WalletRelyingPartyAccessCertificate",
        "Custom",
    }
)

KEY_ATTESTATION_CONTEXT = "WalletProviderAttestation"
CREDENTIAL_OFFER_REQUEST_CONTEXT = "WalletRelyingPartyAccessCertificate"


def _validator_config() -> Dict[str, Any]:
    """Returns the ``trust_validator`` configuration section (or ``{}``)."""
    return CONFIGURATION.get("trust_validator") or {}


def trust_context(name: str, default: str) -> str:
    """Returns the trust validator context configured for a use case.

    Args:
        name: Key under ``trust_validator.contexts``.
        default: Value used when not configured.

    Returns:
        The verification context.
    """
    return _validator_config().get("contexts", {}).get(name, default)


def trust_use_case(name: str) -> Optional[str]:
    """Returns the trust validator ``useCase`` configured for a use case.

    Only needed when the configured context is ``Custom``.

    Args:
        name: Key under ``trust_validator.use_cases``.

    Returns:
        The use case, or ``None``.
    """
    return _validator_config().get("use_cases", {}).get(name)


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


def _check_validity(certificate: x509.Certificate, now: datetime.datetime, label: str) -> None:
    """Checks that ``now`` is within a certificate's validity period.

    Args:
        certificate: Certificate to check.
        now: Current UTC time.
        label: Description used in errors.

    Raises:
        CertificateVerificationError: If the certificate is not yet valid or expired.
    """
    not_before, not_after = certificate_validity(certificate)
    if now < not_before:
        raise CertificateVerificationError(f"{label} not yet valid. Valid from: {not_before}")
    if now > not_after:
        raise CertificateVerificationError(f"{label} expired. Valid until: {not_after}")


def _check_is_ca(certificate: x509.Certificate, label: str) -> None:
    """Checks that a certificate may sign other certificates.

    Args:
        certificate: Intermediate certificate from the chain.
        label: Description used in errors.

    Raises:
        CertificateVerificationError: Without ``basicConstraints`` ``cA=TRUE``
            (a leaf certificate must not act as an issuer).
    """
    try:
        is_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        raise CertificateVerificationError(f"{label} is not a CA certificate")


def _check_issued_by(certificate: x509.Certificate, issuer: x509.Certificate, label: str) -> None:
    """Checks that ``certificate`` was signed by ``issuer``.

    Args:
        certificate: Subject certificate.
        issuer: Candidate issuer certificate.
        label: Description used in errors.

    Raises:
        CertificateVerificationError: If the issuer name or signature does not match.
    """
    try:
        certificate.verify_directly_issued_by(issuer)
    except (ValueError, TypeError) as e:
        raise CertificateVerificationError(f"{label} not issued by {issuer.subject}: {e}") from e
    except Exception as e:  # InvalidSignature
        raise CertificateVerificationError(f"{label} signature invalid") from e


def _load_certificates(chain_der: Sequence[bytes]) -> List[x509.Certificate]:
    """Parses DER certificates.

    Args:
        chain_der: DER certificates.

    Returns:
        The parsed certificates.

    Raises:
        CertificateVerificationError: If an entry is not a valid certificate.
    """
    try:
        return [x509.load_der_x509_certificate(der, default_backend()) for der in chain_der]
    except ValueError as e:
        raise CertificateVerificationError(f"Invalid certificate in x5c chain: {e}") from e


def verify_chain_against_trusted_CAs(chain_der: Sequence[bytes]) -> x509.Certificate:
    """Verifies a certificate chain against the local trusted CA store.

    The chain is walked from the leaf. Each certificate must be valid now and
    be signed either by a trusted CA (which ends the walk) or by the next
    certificate in the chain.

    Args:
        chain_der: DER certificates, leaf first.

    Returns:
        The verified leaf certificate.

    Raises:
        CertificateVerificationError: If the chain does not lead to a valid
            trusted CA, a signature is invalid or a certificate is not valid now.
    """
    if not chain_der:
        raise CertificateVerificationError("Empty certificate chain")
    if not trusted_CAs:
        raise CertificateVerificationError("No trusted CAs loaded")

    chain = _load_certificates(chain_der)
    now = datetime.datetime.now(datetime.timezone.utc)

    for position, certificate in enumerate(chain):
        label = "Certificate" if position == 0 else f"Chain certificate {position}"
        _check_validity(certificate, now, label)

        ca_info = trusted_CAs.get(certificate.issuer)
        if ca_info is not None:
            _check_issued_by(certificate, ca_info["certificate"], label)
            _check_validity(ca_info["certificate"], now, "Trusted CA certificate")
            logger.debug(f"Certificate chain anchored in trusted CA {certificate.issuer}")
            return chain[0]

        if position + 1 >= len(chain):
            raise CertificateVerificationError(
                f"Certificate not issued by a trusted CA. Issuer: {certificate.issuer}"
            )
        _check_is_ca(chain[position + 1], f"Chain certificate {position + 1}")
        _check_issued_by(certificate, chain[position + 1], label)

    raise CertificateVerificationError("Certificate chain does not lead to a trusted CA")


def verify_certificate_against_trusted_CA(certificate_der: bytes) -> x509.Certificate:
    """Verifies a single certificate against the local trusted CA store.

    Args:
        certificate_der: DER encoded certificate.

    Returns:
        The verified certificate.

    Raises:
        CertificateVerificationError: If verification fails.
    """
    return verify_chain_against_trusted_CAs([certificate_der])


def call_trust_validator(
    url: str,
    chain: List[str],
    verification_context: str,
    timeout: int = 10,
    use_case: Optional[str] = None,
) -> bool:
    """Asks the trust validator service whether a certificate chain is trusted.

    Args:
        url: Trust validator ``/trust`` endpoint.
        chain: Certificate chain (base64 DER entries, leaf first).
        verification_context: One of :data:`VERIFICATION_CONTEXTS`.
        timeout: Request timeout in seconds.
        use_case: Optional ``useCase`` (required by the ``Custom`` context).

    Returns:
        The ``trusted`` flag of the response. When ``False`` the validator's
        ``error`` explanation is logged.

    Raises:
        requests.HTTPError: If the service answers ``400`` / ``500``; the
            ``description`` from the error body is logged first.
    """
    if verification_context not in VERIFICATION_CONTEXTS:
        logger.warning(f"Unknown trust validator verificationContext: {verification_context}")

    query: Dict[str, Any] = {"chain": chain, "verificationContext": verification_context}
    if use_case:
        query["useCase"] = use_case

    response = requests.post(
        url,
        json=query,
        headers={"accept": "application/json", "Content-Type": "application/json"},
        timeout=timeout,
    )
    if not response.ok:
        try:
            description = response.json().get("description")
        except ValueError:
            description = response.text
        logger.error(f"Trust validator HTTP {response.status_code} ({verification_context}): {safe(description)}")
    response.raise_for_status()

    body = response.json()
    trusted = bool(body.get("trusted", False))
    if not trusted:
        logger.info(f"Trust validator: chain not trusted ({verification_context}): {safe(body.get('error'))}")
    return trusted


def _trusted_by_validator(x5c_chain: List[str], verification_context: str, use_case: Optional[str]) -> bool:
    """Asks the trust validator, if enabled, whether the chain is trusted.

    Args:
        x5c_chain: Base64 DER chain, leaf first.
        verification_context: Trust validator context.
        use_case: Optional trust validator use case.

    Returns:
        ``True`` only when the validator is enabled and confirms the chain;
        validator errors are logged and count as ``False``.
    """
    validator = _validator_config()
    if not validator.get("enabled") or not validator.get("url"):
        return False
    try:
        trusted = call_trust_validator(
            url=validator["url"], chain=x5c_chain, verification_context=verification_context, use_case=use_case
        )
    except Exception as e:
        logger.warning(f"Trust validator call failed, falling back to local trusted CAs: {safe(e)}")
        return False
    if not trusted:
        logger.info("Trust validator did not confirm the chain, falling back to local trusted CAs")
    return trusted


def verify_x5c_chain(
    x5c_chain: List[str], verification_context: str, use_case: Optional[str] = None
) -> x509.Certificate:
    """Establishes trust in an ``x5c`` chain (trust validator, then local CAs).

    Args:
        x5c_chain: ``x5c`` header value (base64 DER, leaf first).
        verification_context: Trust validator context.
        use_case: Optional trust validator use case.

    Returns:
        The trusted leaf certificate.

    Raises:
        ValueError: If a chain entry is not valid base64.
        CertificateVerificationError: If an entry is not a certificate, or
            neither the trust validator nor the local trusted CAs accept the chain.
    """
    try:
        chain_der = [b64url_decode(entry) for entry in x5c_chain]
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding in x5c: {e}") from e

    if _trusted_by_validator(x5c_chain, verification_context, use_case):
        logger.debug(f"x5c chain trusted by the trust validator ({verification_context})")
        return _load_certificates(chain_der[:1])[0]

    try:
        certificate = verify_chain_against_trusted_CAs(chain_der)
        logger.debug(f"x5c chain trusted by local CA store: {certificate.subject.rfc4514_string()}")
        return certificate
    except CertificateVerificationError as e:
        logger.error(f"Certificate chain verification failed: {safe(e)}")
        raise


# ---------------------------------------------------------------------------
# JWT verification
# ---------------------------------------------------------------------------


#: Signature algorithms accepted for x5c-signed JWTs when the caller sets no
#: narrower list (asymmetric only: never ``none`` or HMAC).
X5C_SIGNING_ALGORITHMS = ("ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA")


def _x5c_header(jwt_raw: str, allowed_algorithms: Optional[List[str]]) -> Tuple[str, List[str]]:
    """Validates the JOSE header of an ``x5c``-signed JWT.

    Args:
        jwt_raw: Compact JWT.
        allowed_algorithms: Permitted ``alg`` values; :data:`X5C_SIGNING_ALGORITHMS`
            when ``None``.

    Returns:
        ``(alg, x5c_chain)``.

    Raises:
        ValueError: If ``alg`` is missing / not allowed, or ``x5c`` is
            missing or not a non-empty list.
    """
    # The x5c chain in the header is the verification key: the caller trusts
    # the chain first, then verifies the signature with its leaf key.
    unverified_header = jwt.get_unverified_header(jwt_raw)  # NOSONAR
    logger.debug(f"JWT header (unverified): {safe(unverified_header, 500)}")

    # Validate algorithm before using it (prevents algorithm confusion attacks).
    alg = unverified_header.get("alg")
    if not alg:
        logger.error("Algorithm not specified in JWT header")
        raise ValueError("Algorithm not specified in JWT header")

    allowed = list(allowed_algorithms or X5C_SIGNING_ALGORITHMS)
    if alg not in allowed:
        logger.error(f"Algorithm '{alg}' not in allowed list: {allowed}")
        raise ValueError(f"Algorithm '{alg}' not allowed. Permitted algorithms: {allowed}")

    x5c_chain = unverified_header.get("x5c")
    if not x5c_chain:
        logger.error("x5c header not found in JWT")
        raise ValueError("x5c header not found in JWT")
    if not isinstance(x5c_chain, list):
        logger.error(f"x5c header must be a non-empty array, got: {type(x5c_chain)}")
        raise ValueError("x5c header must be a non-empty array")
    return alg, x5c_chain


def extract_public_key_from_x5c(
    jwt_raw: str,
    allowed_algorithms: Optional[List[str]] = None,
    verification_context: str = KEY_ATTESTATION_CONTEXT,
    use_case: Optional[str] = None,
) -> Tuple[CertificatePublicKeyTypes, str]:
    """Extracts the signing key of a JWT after establishing trust in its ``x5c`` chain.

    Args:
        jwt_raw: Compact JWT.
        allowed_algorithms: Permitted ``alg`` values; :data:`X5C_SIGNING_ALGORITHMS`
            when ``None``.
        verification_context: Trust validator context.
        use_case: Optional trust validator use case.

    Returns:
        ``(public_key, alg)``.

    Raises:
        ValueError: If the header is malformed or the algorithm is not allowed.
        CertificateVerificationError: If the chain is not trusted.
    """
    alg, x5c_chain = _x5c_header(jwt_raw, allowed_algorithms)
    certificate = verify_x5c_chain(x5c_chain, verification_context, use_case)
    return certificate.public_key(), alg


def verify_jwt_with_x5c(
    jwt_raw: str,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
    allowed_algorithms: Optional[List[str]] = None,
    verify_exp: bool = True,
    verification_context: str = KEY_ATTESTATION_CONTEXT,
    use_case: Optional[str] = None,
    required_claims: Sequence[str] = (),
) -> Dict[str, Any]:
    """Verifies a JWT signed with a trusted ``x5c`` certificate chain.

    Args:
        jwt_raw: Compact JWT.
        audience: Expected audience claim (validated if provided).
        issuer: Expected issuer claim (validated if provided).
        allowed_algorithms: Permitted signing algorithms.
        verify_exp: Whether to verify expiration.
        verification_context: Trust validator context.
        use_case: Optional trust validator use case.
        required_claims: Claims that must be present (e.g. ``exp``, ``iat``).

    Returns:
        The decoded claims.

    Raises:
        ValueError: If the JWT structure is invalid.
        CertificateVerificationError: If the chain is not trusted.
        jwt.InvalidTokenError: If signature or claims validation fails.
    """
    public_key, alg = extract_public_key_from_x5c(jwt_raw, allowed_algorithms, verification_context, use_case)
    logger.debug(f"Expected audience: {audience}, Expected issuer: {issuer}, verify_exp: {verify_exp}")
    claims = jwt.decode(
        jwt_raw,
        key=public_key,
        algorithms=[alg],
        audience=audience,
        issuer=issuer,
        options={"verify_exp": verify_exp, "require": list(required_claims)},
    )
    logger.debug("JWT signature and claims verified successfully")
    return claims


def x5c_leaf_certificate(jwt_raw: str) -> Tuple[x509.Certificate, str]:
    """Returns the (not yet trusted) ``x5c`` leaf certificate and ``alg`` of a JWT.

    Args:
        jwt_raw: Compact JWT.

    Returns:
        ``(certificate, alg)``.

    Raises:
        ValueError: If the ``x5c`` header is missing or malformed.
    """
    # Returns the not-yet-trusted signer; callers check the certificate and
    # then verify the signature with its key (verify_and_decode_sdjwt).
    unverified_header = jwt.get_unverified_header(jwt_raw)  # NOSONAR
    x5c_chain = unverified_header.get("x5c")
    if not x5c_chain:
        raise ValueError("x5c header not found in JWT")
    certificate = x509.load_der_x509_certificate(b64_decode_x5c(x5c_chain[0]), default_backend())
    return certificate, unverified_header["alg"]


def verify_and_decode_sdjwt(sd_jwt: str, is_trusted_signer: Callable[[x509.Certificate], bool]) -> Dict[str, Any]:
    """Verifies an SD-JWT's issuer signature and decodes its payload.

    The signer certificate (``x5c`` leaf) must be accepted by
    ``is_trusted_signer`` before the signature is checked with its key.

    Args:
        sd_jwt: SD-JWT in compact serialization.
        is_trusted_signer: Decides whether the signer certificate is trusted.

    Returns:
        The decoded issuer-signed JWT payload.

    Raises:
        CertificateVerificationError: If the signer certificate is not trusted.
        ValueError: If ``x5c`` is missing / malformed or the key type is
            unsupported.
        jwt.InvalidTokenError: If signature verification fails.
    """
    issuer_jwt = SDJWTHolder(sd_jwt)._unverified_input_sd_jwt
    certificate, alg = x5c_leaf_certificate(issuer_jwt)
    if alg not in X5C_SIGNING_ALGORITHMS:
        raise ValueError(f"Algorithm '{alg}' not allowed")
    if not is_trusted_signer(certificate):
        raise CertificateVerificationError(f"Untrusted SD-JWT signer: {certificate.subject.rfc4514_string()}")
    public_key = certificate.public_key()
    if not isinstance(public_key, SUPPORTED_PUBLIC_KEY_TYPES):
        raise ValueError(f"Unsupported key type: {type(public_key)}")
    return jwt.decode(issuer_jwt, key=public_key, algorithms=[alg])

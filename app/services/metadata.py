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
"""Issuer metadata: loading at start-up, trusted CAs, and signed metadata.

:func:`setup_metadata` and :func:`setup_trusted_cas` fill the shared
registries in :mod:`app.core.state` in place.

Attributes:
    METADATA_DIR: Directory holding ``credentials_supported/`` and the
        frontend metadata templates.
    INTERNAL_METADATA_KEYS: Issuer-only keys stripped from public metadata.
"""

from __future__ import annotations

import base64
import copy
import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from app.core import state
from app.core.config import CONFIGURATION
from app.utils.crypto import certificate_validity
from app.utils.encoding import b64url_uint, urlsafe_b64encode_nopad
from app.utils.frontend import frontend_config

logger = logging.getLogger(__name__)

METADATA_DIR = Path(__file__).resolve().parent.parent / "metadata_config"

INTERNAL_METADATA_KEYS = {
    "issuer_conditions",
    "issuer_config",
    "overall_issuer_conditions",
    "source",
    "selective_disclosure",
}
ENCRYPTION_ENC_VALUES = ["A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512", "ECDH-ES"]
SIGNED_METADATA_TYP = "openidvci-issuer-metadata+jwt"

Json = Union[Dict[str, Any], List[Any], str, Any]


# ---------------------------------------------------------------------------
# JSON transformation helpers
# ---------------------------------------------------------------------------


def remove_keys(obj: Json, keys_to_remove: set[str]) -> Json:
    """Recursively removes keys from a JSON structure.

    Containers left empty after removal become ``None`` (and are dropped
    from their parent list).

    Args:
        obj: JSON value.
        keys_to_remove: Keys to delete at any depth.

    Returns:
        The cleaned structure.
    """
    if isinstance(obj, dict):
        new_obj = {k: remove_keys(v, keys_to_remove) for k, v in obj.items() if k not in keys_to_remove}
        return new_obj or None
    if isinstance(obj, list):
        new_list = [item for item in (remove_keys(i, keys_to_remove) for i in obj) if item is not None]
        return new_list or None
    return obj


def replace_domain(obj: Json, old: str, new: str) -> Json:
    """Recursively replaces ``old`` by ``new`` in every string of a JSON structure.

    Args:
        obj: JSON value.
        old: Text to replace.
        new: Replacement.

    Returns:
        A new structure with replaced strings.
    """
    if isinstance(obj, dict):
        return {k: replace_domain(v, old, new) for k, v in obj.items()}
    if isinstance(obj, list):
        return [replace_domain(i, old, new) for i in obj]
    if isinstance(obj, str):
        return obj.replace(old, new)
    return obj


def fix_key_attestations(data: Json) -> Json:
    """Replaces ``key_attestations_required: null`` with ``{}`` in place.

    Args:
        data: JSON structure (mutated).

    Returns:
        ``data``.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "key_attestations_required" and value is None:
                data[key] = {}
            else:
                fix_key_attestations(value)
    elif isinstance(data, list):
        for item in data:
            fix_key_attestations(item)
    return data


# ---------------------------------------------------------------------------
# Start-up loading
# ---------------------------------------------------------------------------


def _build_credential_encryption_metadata(key_bytes: bytes) -> Dict[str, Any]:
    """Builds the ``credential_request_encryption`` metadata block.

    Only the public coordinates of the P-256 key are exposed; the ``kid`` is
    the RFC 7638 JWK thumbprint (SHA-256).

    Args:
        key_bytes: PEM encoded EC private key.

    Returns:
        The metadata block.

    Raises:
        ValueError: If the key is not an EC private key.
    """
    private_key = load_pem_private_key(key_bytes, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("credential_encryption_key must be a P-256 EC private key")

    nums = private_key.public_key().public_numbers()
    key_size = (private_key.key_size + 7) // 8
    x_b64 = b64url_uint(nums.x, key_size)
    y_b64 = b64url_uint(nums.y, key_size)

    thumbprint_json = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": x_b64, "y": y_b64}, separators=(",", ":"), sort_keys=True
    ).encode()
    kid = urlsafe_b64encode_nopad(hashlib.sha256(thumbprint_json).digest())

    logger.info("credential_request_encryption metadata built successfully (kid=%s, crv=P-256)", kid)
    return {
        "jwks": {
            "keys": [
                {"kty": "EC", "use": "enc", "alg": "ECDH-ES", "crv": "P-256", "x": x_b64, "y": y_b64, "kid": kid}
            ]
        },
        "enc_values_supported": list(ENCRYPTION_ENC_VALUES),
        "encryption_required": False,
    }


def _load_json(path: Path) -> Any:
    """Reads a UTF-8 JSON file.

    Args:
        path: File path.

    Returns:
        The parsed JSON.
    """
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def setup_metadata(metadata_dir: Path | str = METADATA_DIR) -> None:
    """Loads the credential configurations into :mod:`app.core.state`.

    * :data:`~app.core.state.oidc_metadata` receives the full configurations
      read from ``credentials_supported/*.json`` (including issuer-only keys
      such as ``issuer_config``) for the issuance logic.
    * :data:`~app.core.state.oidc_metadata_clean` receives the public view:
      configurations stripped of issuer-only keys, plus the
      ``credential_request_encryption`` block derived from the configured
      encryption key. It is the source of the per-frontend metadata
      (:mod:`app.services.frontend_metadata`).

    Args:
        metadata_dir: Directory containing ``credentials_supported/``.

    Raises:
        FileNotFoundError: If the directory is missing.
        json.JSONDecodeError: If a file is not valid JSON.
        Exception: If the encryption metadata cannot be built.
    """
    credentials_dir = Path(metadata_dir) / "credentials_supported"
    try:
        credentials_supported: Dict[str, Any] = {}
        for file in sorted(os.listdir(credentials_dir)):
            if file.endswith("json"):
                credentials_supported.update(_load_json(credentials_dir / file))
    except FileNotFoundError as e:
        logger.exception(f"Metadata Error: file not found. \n{e}")
        raise
    except json.JSONDecodeError as e:
        logger.exception(f"Metadata Error: Metadata Unable to decode JSON. \n{e}")
        raise
    except Exception as e:
        logger.exception(f"Metadata Error: An unexpected error occurred. \n{e}")
        raise

    logger.info("Setting up credential_request_encryption")
    try:
        credential_request_encryption = _build_credential_encryption_metadata(
            CONFIGURATION["keys"]["credential_encryption_key"]
        )
        logger.info("credential_request_encryption: %s", json.dumps(credential_request_encryption, indent=2))
    except Exception as e:
        logger.exception("Failed to build credential_request_encryption metadata: %s", e)
        raise

    state.replace_contents(state.oidc_metadata, {"credential_configurations_supported": credentials_supported})
    state.replace_contents(
        state.oidc_metadata_clean,
        {
            "credential_configurations_supported": fix_key_attestations(
                remove_keys(copy.deepcopy(credentials_supported), INTERNAL_METADATA_KEYS)
            ),
            "credential_request_encryption": credential_request_encryption,
        },
    )


def _load_trusted_ca(pem_data: bytes) -> tuple[x509.Name, Dict[str, Any]]:
    """Parses a trusted CA certificate.

    Args:
        pem_data: PEM certificate.

    Returns:
        ``(subject_name, ca_info)`` where ``ca_info`` holds the certificate,
        its public key and its validity bounds (UTC).

    Raises:
        ValueError: If ``pem_data`` is not a PEM certificate.
    """
    certificate = x509.load_pem_x509_certificate(pem_data, default_backend())
    not_valid_before, not_valid_after = certificate_validity(certificate)
    return certificate.subject, {
        "certificate": certificate,
        "public_key": certificate.public_key(),
        "not_valid_before": not_valid_before,
        "not_valid_after": not_valid_after,
    }


def setup_trusted_cas(trusted_cas_path: Optional[str] = None) -> None:
    """Loads every ``*.pem`` CA certificate into :data:`app.core.state.trusted_CAs`.

    Args:
        trusted_cas_path: Directory of PEM files; defaults to
            ``CONFIGURATION["trusted_CAs_path"]``.

    Raises:
        FileNotFoundError: If the directory does not exist.
        ValueError: If a file is not a valid PEM certificate.
    """
    directory = trusted_cas_path or CONFIGURATION["trusted_CAs_path"]
    try:
        ec_keys: Dict[x509.Name, Dict[str, Any]] = {}
        for file in os.listdir(directory):
            if file.endswith("pem"):
                with open(os.path.join(directory, file), "rb") as pem_file:
                    subject, ca_info = _load_trusted_ca(pem_file.read())
                ec_keys[subject] = ca_info
    except FileNotFoundError as e:
        logger.exception(f"TrustedCA Error: file not found.\n {e}")
        raise
    except Exception as e:
        logger.exception(f"TrustedCA Error: An unexpected error occurred.\n {e}")
        raise

    state.replace_contents(state.trusted_CAs, ec_keys)


# ---------------------------------------------------------------------------
# Signed metadata (OpenID4VCI 12.2.3)
# ---------------------------------------------------------------------------


class MetadataSigningError(Exception):
    """Raised when issuer metadata cannot be signed.

    Args:
        message: Error summary returned to the client.
        details: Optional technical details.
    """

    def __init__(self, message: str, details: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


def signing_algorithm(private_key: Any) -> str:
    """Chooses the JWS algorithm matching a private key.

    Args:
        private_key: EC, RSA or Ed25519 private key.

    Returns:
        ``ES256/384/512``, ``RS256/384/512`` or ``EdDSA``.

    Raises:
        MetadataSigningError: For unsupported key types.
    """
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return {"secp384r1": "ES384", "secp521r1": "ES512"}.get(private_key.curve.name, "ES256")
    if isinstance(private_key, rsa.RSAPrivateKey):
        if private_key.key_size >= 4096:
            return "RS512"
        if private_key.key_size >= 3072:
            return "RS384"
        return "RS256"
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return "EdDSA"
    raise MetadataSigningError(f"Unsupported key type: {type(private_key).__name__}")


def sign_issuer_metadata(metadata: Dict[str, Any], issuer_frontend_id: str, iss: Optional[str] = None) -> str:
    """Signs issuer metadata as a JWT with the frontend's metadata key.

    The payload holds ``sub`` (credential issuer identifier), ``iat``,
    optional ``iss`` and every metadata parameter as a top-level claim; the
    signing certificate is sent in ``x5c``.

    Args:
        metadata: Issuer metadata.
        issuer_frontend_id: Frontend whose identifier, key and certificate are used.
        iss: Optional party attesting to the claims.

    Returns:
        The signed metadata JWT.

    Raises:
        MetadataSigningError: If the key / certificate cannot be loaded or
            the key type is unsupported.
        KeyError: If the frontend is not configured.
        jwt.PyJWTError: If encoding fails.
    """
    frontend = frontend_config(issuer_frontend_id)
    payload: Dict[str, Any] = {
        "sub": frontend["url"],
        "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
    }
    if iss:
        payload["iss"] = iss
    payload.update(metadata)

    try:
        private_key = serialization.load_pem_private_key(
            frontend["metadata_signing_key"], password=frontend["metadata_signing_key_password"]
        )
    except Exception as e:
        logger.exception("Error loading metadata signing key")
        raise MetadataSigningError("Failed to load private key", str(e)) from e

    algorithm = signing_algorithm(private_key)

    try:
        certificate = x509.load_pem_x509_certificate(frontend["metadata_access_certificate"])
        cert_b64 = base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("utf-8")
    except Exception as e:
        logger.exception("Error loading metadata certificate")
        raise MetadataSigningError("Failed to load certificate", str(e)) from e

    return jwt.encode(
        payload,
        private_key,
        algorithm=algorithm,
        headers={"typ": SIGNED_METADATA_TYP, "alg": algorithm, "x5c": [cert_b64]},
    )

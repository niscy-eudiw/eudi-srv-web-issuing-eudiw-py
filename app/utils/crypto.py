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
"""Elliptic-curve key helpers shared by the credential formatters and JWK code."""

from __future__ import annotations

import datetime
from typing import Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app.utils.encoding import int_to_bytes

#: Mapping of ``cryptography`` curve names to JOSE ``crv`` identifiers.
CURVE_TO_JWK = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}

EcKey = Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]


def ec_public_numbers(key: EcKey) -> ec.EllipticCurvePublicNumbers:
    """Returns the public numbers of an EC public or private key.

    Args:
        key: EC key.

    Returns:
        The public numbers (x, y, curve).
    """
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.private_numbers().public_numbers
    return key.public_numbers()


def ec_coordinates(key: EcKey, min_length: int = 32) -> Tuple[bytes, bytes]:
    """Extracts the big-endian x / y coordinates of an EC key.

    Args:
        key: EC public or private key.
        min_length: Left-pad each coordinate with zeros to at least this length.

    Returns:
        ``(x, y)`` byte strings.
    """
    numbers = ec_public_numbers(key)
    return int_to_bytes(numbers.x).rjust(min_length, b"\x00"), int_to_bytes(numbers.y).rjust(
        min_length, b"\x00"
    )


def jwk_curve(key: EcKey) -> Optional[str]:
    """Returns the JOSE ``crv`` name of an EC key.

    Args:
        key: EC key.

    Returns:
        ``"P-256"``, ``"P-384"``, ``"P-521"`` or ``None`` if unsupported.
    """
    return CURVE_TO_JWK.get(key.curve.name)


def private_value_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Returns the private scalar ``d`` as minimal big-endian bytes.

    Args:
        key: EC private key.

    Returns:
        ``d`` encoded as bytes.
    """
    return int_to_bytes(key.private_numbers().private_value)


def certificate_validity(certificate: x509.Certificate) -> Tuple[datetime.datetime, datetime.datetime]:
    """Returns a certificate's validity period as timezone-aware UTC datetimes.

    Uses ``not_valid_before_utc`` / ``not_valid_after_utc`` (cryptography >= 42)
    and falls back to the naive properties of older releases.

    Args:
        certificate: X.509 certificate.

    Returns:
        ``(not_before, not_after)`` in UTC.
    """

    def utc(aware_name: str, naive_name: str) -> datetime.datetime:
        aware = getattr(certificate, aware_name, None)
        if aware is not None:
            return aware
        return getattr(certificate, naive_name).replace(tzinfo=datetime.timezone.utc)

    return utc("not_valid_before_utc", "not_valid_before"), utc("not_valid_after_utc", "not_valid_after")

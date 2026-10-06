"""Helpers building throw-away X.509 certificates and x5c chains for tests."""

import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from app.utils.crypto import certificate_validity

NOW = datetime.datetime.now(datetime.timezone.utc)


def make_name(common_name):
    """Builds an X.509 name with only a common name."""
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_cert(subject, issuer, public_key, signing_key, *, ca, not_before=None, not_after=None):
    """Creates a certificate for ``subject`` signed by ``signing_key`` as ``issuer``."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(make_name(subject))
        .issuer_name(make_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - datetime.timedelta(days=1))
        .not_valid_after(not_after or NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(signing_key, hashes.SHA256())


def x5c(*certs):
    """Encodes certificates as an ``x5c`` header value (base64 DER, leaf first)."""
    return [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in certs]


def ca_entry(cert):
    """Builds a trusted CA store entry for ``app.core.state.trusted_CAs``."""
    not_valid_before, not_valid_after = certificate_validity(cert)
    return {
        "certificate": cert,
        "public_key": cert.public_key(),
        "not_valid_before": not_valid_before,
        "not_valid_after": not_valid_after,
    }

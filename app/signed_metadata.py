# coding: latin-1
###############################################################################
# Copyright (c) 2026 European Commission
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
from flask import (
    Blueprint,
    Response,
    jsonify,
    request,
    session,
    current_app,
    redirect,
    render_template,
    url_for,
)

from datetime import datetime, timedelta
import jwt
import os
from cryptography import x509
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from flask_cors import CORS
from .app_config.config_service import ConfService as cfgservice
from .app_config.config_countries import ConfFrontend as cfgfrontend
from app_config.config_countries import ConfCountries as cfgcountries

metadata = Blueprint("metadata", __name__, url_prefix="/metadata")
CORS(metadata)


@metadata.route("metadata_signer", methods=["POST"])
def metadata_signer():
    """
    Signs issuer metadata according to OpenID4VCI specification (12.2.3 Signed Metadata).

    Expects JSON payload with:
    - metadata: dict containing the issuer metadata
    - issuer_frontend_id: string identifier for the credential issuer
    - exp_hours: optional, hours until expiration (default: 24)
    - iss: optional, party attesting to the claims

    Returns signed JWT with:
    - JOSE header: alg, typ
    - Payload: iss (optional), sub, iat, exp (optional), and all metadata as top-level claims
    """
    try:
        print(f"DEBUG: metadata_signer endpoint called")
        data = request.get_json()
        print(f"DEBUG: Received data: {data is not None}")

        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        # Required fields
        metadata_content = data.get("metadata")
        issuer_frontend_id = data.get("issuer_frontend_id")

        print(f"DEBUG: issuer_frontend_id: {issuer_frontend_id}")
        print(f"DEBUG: metadata_content present: {metadata_content is not None}")

        if not metadata_content:
            return jsonify({"error": "metadata is required"}), 400

        if not issuer_frontend_id:
            return jsonify({"error": "issuer_frontend_id is required"}), 400

        if not isinstance(metadata_content, dict):
            return jsonify({"error": "metadata must be a JSON object"}), 400

        # Optional fields
        # exp_hours = data.get("exp_hours", 24)  # Default 24 hours
        iss_claim = data.get("iss")  # Optional issuer claim

        print(f"DEBUG: Building payload...")
        payload = {
            "sub": cfgfrontend.registered_frontends[issuer_frontend_id][
                "url"
            ],  # REQUIRED: Credential Issuer Identifier
            "iat": int(datetime.utcnow().timestamp()),  # REQUIRED: Issued at
        }
        print(f"DEBUG: Payload sub: {payload['sub']}")

        # Add optional iss claim
        if iss_claim:
            payload["iss"] = iss_claim

        # Add optional exp claim
        """ if exp_hours:
            exp_time = datetime.utcnow() + timedelta(hours=exp_hours)
            payload["exp"] = int(exp_time.timestamp()) """

        # Add all metadata parameters as top-level claims in the payload
        # This is REQUIRED per the spec
        payload.update(metadata_content)
        print(f"DEBUG: Payload updated with metadata")

        print(f"DEBUG: About to load private key")
        print(
            f"DEBUG: Key path: {cfgcountries.supported_countries['FC']['pid_mdoc_privkey']}",
            flush=True,
        )

        try:
            with open(
                "/home/pid.issuer/pidprovider/dev/eudi-srv-web-issuing-eudiw-py/app/private/PID-DS-03.key",
                "rb",
            ) as key_file:
                key_data = key_file.read()
                print(f"DEBUG: Successfully read key file, size: {len(key_data)} bytes")

                private_key = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                )
                print(f"DEBUG: Successfully loaded private key")
        except Exception as e:
            print(f"DEBUG: Error loading key: {type(e).__name__}: {str(e)}")
            import traceback

            traceback.print_exc()
            return (
                jsonify({"error": "Failed to load private key", "details": str(e)}),
                500,
            )

        if not private_key:
            print(f"DEBUG: private_key is None or False")
            return jsonify({"error": "Signing key not configured"}), 500

        # Determine algorithm based on key type by checking attributes
        print(f"DEBUG: Detecting key type...")
        print(f"DEBUG: private_key type: {type(private_key)}")
        print(f"DEBUG: private_key type name: {type(private_key).__name__}")

        key_class_name = type(private_key).__name__
        print(f"DEBUG: key_class_name = {key_class_name}")

        print(
            f"DEBUG: Checking for key_size attribute: {hasattr(private_key, 'key_size')}"
        )
        print(f"DEBUG: Checking for curve attribute: {hasattr(private_key, 'curve')}")

        if hasattr(private_key, "curve"):  # EC key - check this FIRST
            print(f"DEBUG: Detected EC key")
            curve_name = private_key.curve.name
            print(f"DEBUG: EC curve name: {curve_name}")
            if curve_name == "secp256r1":
                algorithm = "ES256"
            elif curve_name == "secp384r1":
                algorithm = "ES384"
            elif curve_name == "secp521r1":
                algorithm = "ES512"
            else:
                algorithm = "ES256"  # Default for EC keys
            print(f"DEBUG: Selected algorithm: {algorithm}")
        elif hasattr(private_key, "key_size"):  # RSA key - check this SECOND
            print(f"DEBUG: Detected RSA key")
            key_size = private_key.key_size
            print(f"DEBUG: RSA key size: {key_size}")
            if key_size >= 4096:
                algorithm = "RS512"
            elif key_size >= 3072:
                algorithm = "RS384"
            else:
                algorithm = "RS256"
            print(f"DEBUG: Selected algorithm: {algorithm}")
        elif key_class_name == "Ed25519PrivateKey":  # EdDSA key
            print(f"DEBUG: Detected Ed25519 key")
            algorithm = "EdDSA"
            print(f"DEBUG: Selected algorithm: {algorithm}")
        else:
            print(f"DEBUG: Unsupported key type detected")
            return jsonify({"error": f"Unsupported key type: {key_class_name}"}), 500

        print(f"DEBUG: Final algorithm: {algorithm}")

        # Validate algorithm is not 'none' or symmetric
        forbidden_algs = ["none", "HS256", "HS384", "HS512"]
        if algorithm in forbidden_algs:
            print(f"DEBUG: Algorithm {algorithm} is forbidden")
            return (
                jsonify(
                    {
                        "error": f"Algorithm {algorithm} is not allowed for signed metadata"
                    }
                ),
                500,
            )

        try:
            from cryptography.hazmat.primitives import (
                serialization as crypto_serialization,
            )

            private_key_pem = private_key.private_bytes(
                encoding=crypto_serialization.Encoding.PEM,
                format=crypto_serialization.PrivateFormat.PKCS8,
                encryption_algorithm=crypto_serialization.NoEncryption(),
            )
            print(
                f"DEBUG: Private key serialized to PEM, length: {len(private_key_pem)} bytes"
            )
        except Exception as e:
            print(f"DEBUG: Error serializing key: {type(e).__name__}: {str(e)}")
            import traceback

            traceback.print_exc()
            return (
                jsonify(
                    {"error": "Failed to serialize private key", "details": str(e)}
                ),
                500,
            )

        print(f"DEBUG: Loading certificate for x5c header")
        try:
            cert_path = "/home/pid.issuer/pidprovider/dev/eudi-srv-web-issuing-eudiw-py/app/private/PID-DS-03.crt"
            with open(cert_path, "rb") as cert_file:
                cert_data = cert_file.read()
                print(
                    f"DEBUG: Successfully read certificate file, size: {len(cert_data)} bytes"
                )

                # Load the certificate
                certificate = x509.load_pem_x509_certificate(cert_data)
                print(f"DEBUG: Successfully loaded certificate")

                # Encode certificate as base64 (DER format, without PEM headers)
                cert_der = certificate.public_bytes(serialization.Encoding.DER)
                cert_b64 = base64.b64encode(cert_der).decode("utf-8")
                print(f"DEBUG: Certificate encoded to base64, length: {len(cert_b64)}")

        except Exception as e:
            print(f"DEBUG: Error loading certificate: {type(e).__name__}: {str(e)}")
            import traceback

            traceback.print_exc()
            return (
                jsonify({"error": "Failed to load certificate", "details": str(e)}),
                500,
            )

        print(f"DEBUG: About to encode JWT")
        print(f"DEBUG: Payload keys: {list(payload.keys())}", flush=True)

        signed_metadata = jwt.encode(
            payload,
            private_key_pem,
            algorithm=algorithm,
            headers={
                "typ": "openidvci-issuer-metadata+jwt",  # REQUIRED: Explicit type
                "alg": algorithm,  # REQUIRED: Algorithm identifier
                "x5c": [cert_b64],
            },
        )

        print(f"DEBUG: JWT encoded successfully")
        print(f"DEBUG: JWT length: {len(signed_metadata)}")

        return (
            jsonify(
                {
                    "signed_metadata": signed_metadata,
                }
            ),
            200,
        )

    except jwt.PyJWTError as e:
        print(f"DEBUG: JWT encoding error: {type(e).__name__}: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": "JWT encoding failed", "details": str(e)}), 500

    except Exception as e:
        print(f"DEBUG: General exception: {type(e).__name__}: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

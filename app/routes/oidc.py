# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
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
"""OpenID4VCI endpoints: authorization method choice, credential,
deferred credential, notification, nonce and credential offers.

The handlers only parse requests and shape responses; the business logic
lives in :mod:`app.services.credential_issuance`,
:mod:`app.services.credential_offer` and :mod:`app.services.auth_server`.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import jwt
import requests
import werkzeug
from authlib.jose import JsonWebEncryption, JsonWebKey
from flask import Blueprint, Response, jsonify, redirect, request, session, url_for
from flask.helpers import make_response
from flask_cors import CORS

from app.core.config import CONFIGURATION
from app.core.security import require_api_key
from app.core.state import oidc_metadata, session_manager
from app.repositories.offer_store import clear_par, credential_offer_references
from app.repositories.status_store import persist_client_status
from app.services.attributes import (
    credential_display_names,
    requested_credential_ids,
    scope2details,
    vct2id,
)
from app.services.auth_server import StatusCheckError, check_status_list_revocation, introspect
from app.services.credential_issuance import (
    DEFERRED_ONLY_CONFIGURATION,
    create_c_nonce,
    decrypt_jwe_credential_request,
    generate_credentials,
)
from app.services.credential_offer import authorization_code_offer, credential_offer_uri
from app.services.oid4vp import fetch_presentation_result, presentation_result_url, validate_presentation_id
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload
from app.utils.ids import generate_unique_id
from app.utils.qr import qr_data_uri, qr_png_base64

oidc = Blueprint("oidc", __name__, url_prefix="/")
CORS(oidc)  # enable CORS on the blue print

logger = logging.getLogger(__name__)

HandlerResult = Union[Response, Tuple[Any, int]]

DEFERRED_INTERVAL_SECONDS = 30
_ANSI_ESCAPE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------


def _bearer_token(auth_header: str) -> Optional[str]:
    """Extracts the token from an ``Authorization`` header value.

    Args:
        auth_header: Header value, e.g. ``"Bearer abc"``.

    Returns:
        The token, or ``None`` if the header has no second part.
    """
    parts = auth_header.split(" ")
    return parts[1] if len(parts) > 1 else None


def _is_introspection_success(result: Any) -> bool:
    """Tells a successful :func:`verify_introspection` result from an error response.

    Args:
        result: Return value of :func:`verify_introspection`.

    Returns:
        ``True`` for ``(session_id: str, client_status)``.
    """
    return isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], str)


def _read_credential_request(invalid_jwt_error: str) -> Union[Dict[str, Any], Response]:
    """Reads a credential request body (JSON, or a JWE with ``application/jwt``).

    Args:
        invalid_jwt_error: ``error`` value returned when decryption fails.

    Returns:
        The request dictionary, or a ``400`` response.
    """
    if request.content_type != "application/jwt":
        return request.get_json()

    jwt_token = request.get_data(as_text=True)
    logger.info(f", Started Credential Request (JWT), Token: {jwt_token}")
    try:
        return decrypt_jwe_credential_request(jwt_token)
    except Exception as e:
        logger.error(f"Failed to decrypt/verify JWT: {str(e)}")
        return make_response(jsonify({"error": invalid_jwt_error}), 400)


# ---------------------------------------------------------------------------
# Validation helpers (return Flask error responses)
# ---------------------------------------------------------------------------


def verify_introspection(bearer_token: str) -> Any:
    """Validates an access token with the authorization server.

    When the access token is a JWT carrying a WIA ``client_status`` and the
    status validator is enabled, the WIA revocation status is checked too.

    Args:
        bearer_token: Access token.

    Returns:
        ``(session_id, client_status)`` on success (``client_status`` may be
        ``None``), otherwise a ``(json_response, status)`` error tuple. A WIA
        that is revoked or whose status cannot be checked yields ``401``.
    """
    try:
        response = introspect(bearer_token)
        response.raise_for_status()
        introspection_data = response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"An error occurred during introspection request: {e}")
        return jsonify({"error": "Failed to validate token with the issuer."}), 502
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON from introspection response.")
        return jsonify({"error": "Invalid response from the introspection endpoint."}), 502

    if not introspection_data.get("active", False):
        return jsonify({"error": "invalid_token"}), 401

    username = introspection_data.get("username")
    if not username:
        logger.error("Token is active but missing username.")
        return jsonify({"error": "invalid_token"}), 401

    # Introspection already confirmed the token is active/well-formed, so an
    # unverified decode here is just claim extraction, not a trust decision.
    client_status = None
    try:
        at_claims = jwt.decode(bearer_token, options={"verify_signature": False})
        client_status = at_claims.get("client_status")
    except jwt.DecodeError:
        logger.info("Access token is not a JWT; no client_status claim available.")

    if client_status and CONFIGURATION["status_validator"]["enabled"]:
        status_list = client_status["status"]["status_list"]
        try:
            revoked = check_status_list_revocation(
                url=CONFIGURATION["status_validator"]["url"],
                status_idx=status_list["idx"],
                status_uri=status_list["uri"],
            )
        except StatusCheckError as e:
            # Fail closed: a WIA whose status cannot be checked is not accepted.
            logger.error(f"WIA client_status could not be checked for session tied to {username}: {e}")
            return jsonify({"error": "invalid_token", "error_description": "Wallet status could not be verified"}), 401
        if revoked:
            logger.error(f"WIA client_status revoked for session tied to {username}")
            return jsonify({"error": "invalid_token"}), 401

    return username, client_status


def verify_credential_request(credential_request: Dict[str, Any]) -> Any:
    """Checks the structure of a credential request.

    Args:
        credential_request: Credential request body.

    Returns:
        The request itself when valid, otherwise a ``(json_response, 400)``
        tuple with ``invalid_credential_request`` or ``invalid_proof``.
    """
    invalid_request = (jsonify({"error": "invalid_credential_request"}), 400)

    if "credential_indentifier" in credential_request:
        return invalid_request
    if "credential_identifier" not in credential_request and "credential_configuration_id" not in credential_request:
        return invalid_request
    if "proof" not in credential_request and "proofs" not in credential_request:
        return jsonify({"error": "invalid_proof"}), 400

    proof = credential_request.get("proof")
    if proof is not None:
        proof_type = proof.get("proof_type")
        if proof_type is None or (proof_type in ("attestation", "jwt") and proof_type not in proof):
            return jsonify({"error": "invalid_proof"}), 400

    return credential_request


def encrypt_response(credential_request: Dict[str, Any], credential_response: Dict[str, Any]) -> Response:
    """Encrypts a credential response as a compact JWE.

    Args:
        credential_request: Request containing ``credential_response_encryption``
            (``jwk``, ``enc`` and ``alg`` in the config or the JWK).
        credential_response: Response body to encrypt.

    Returns:
        An ``application/jwt`` response, or a ``400`` error response.
    """
    encryption_config = credential_request.get("credential_response_encryption", {})

    def error(description: str) -> Response:
        """Builds an ``invalid_credential_response_encryption`` 400 response."""
        return make_response(
            jsonify({"error": "invalid_credential_response_encryption", "error_description": description}),
            400,
        )

    if not encryption_config or not all(k in encryption_config for k in ("jwk", "enc")):
        return error("Missing required fields in credential_response_encryption.")

    alg = encryption_config.get("alg") or encryption_config["jwk"].get("alg")
    if alg is None:
        return error("Missing alg field in credential_response_encryption.")

    try:
        jwe_token = JsonWebEncryption().serialize_compact(
            {"alg": alg, "enc": encryption_config["enc"]},
            json.dumps(credential_response),
            JsonWebKey.import_key(encryption_config["jwk"]),
        )
    except Exception:
        return error("Failed to encrypt with the provided key.")

    response = make_response(jwe_token)
    response.headers["Content-Type"] = "application/jwt"
    return response


# ---------------------------------------------------------------------------
# Shared credential pipeline
# ---------------------------------------------------------------------------


def _issue(validated_request: Dict[str, Any], session_id: str, wia_client_status: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Records the WIA status and generates the credential(s).

    Args:
        validated_request: Validated credential request.
        session_id: Issuance session.
        wia_client_status: ``client_status`` from the access token.

    Returns:
        The credential response dict (possibly with ``error``).
    """
    if wia_client_status:
        session_manager.update_client_status_status(session_id, wia_client_status.get("status"))
        session_manager.update_client_status_exp(session_id, wia_client_status.get("exp"))

    response = generate_credentials(
        credential_request=validated_request, session_id=session_id, wia_client_status=wia_client_status
    )
    if not isinstance(response, dict):
        return {"error": "invalid_proof", "error_description": "Unable to read proof"}
    return response


def _add_notification_id(session_id: str, response: Dict[str, Any]) -> None:
    """Generates a notification id, stores it in the session and adds it to ``response``.

    Args:
        session_id: Issuance session.
        response: Credential response (mutated).
    """
    notification_id = str(uuid.uuid4())
    session_manager.store_notification_id(session_id=session_id, notification_id=notification_id)
    response["notification_id"] = notification_id


def _finish(
    session_id: str,
    response: Dict[str, Any],
    is_deferred: bool,
    encryption_request: Dict[str, Any],
) -> HandlerResult:
    """Persists client status and returns the (optionally encrypted) response.

    Args:
        session_id: Issuance session.
        response: Credential (or deferred) response.
        is_deferred: Whether issuance is deferred (``202``).
        encryption_request: Request whose ``credential_response_encryption``
            governs encryption.

    Returns:
        ``(response, 200 | 202)`` or an encryption error response.
    """
    current_session = session_manager.get_session(session_id=session_id)
    if not is_deferred and current_session and current_session.client_status:
        persist_client_status(session_id, current_session.client_status)

    status = 202 if is_deferred else 200
    body: Any = response
    if "credential_response_encryption" in encryption_request:
        body = encrypt_response(credential_request=encryption_request, credential_response=response)
        if body.status_code != 200:
            return body

    if not is_deferred:
        logger.info(f", Session ID: {session_id}, Credential Issuance Successful")
    return body, status


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _auth_methods(credentials_requested: List[str]) -> Tuple[bool, bool]:
    """Determines which authentication methods support all requested credentials.

    Args:
        credentials_requested: Credential configuration ids.

    Returns:
        ``(pid_auth, country_selection)``.
    """
    supported = CONFIGURATION["credential_auth_methods"]
    pid_auth = all(cred in supported["PID_login"] for cred in credentials_requested)
    country_selection = all(cred in supported["country_selection"] for cred in credentials_requested)
    return pid_auth, country_selection


@oidc.route("/auth_choice", methods=["GET"])
def auth_choice() -> HandlerResult:
    """Starts an issuance session and picks the user authentication method.

    Redirects to the PID (OID4VP) login or country selection when only one
    method fits; otherwise shows the method choice page.

    Returns:
        A redirect, the frontend POST-redirect page, or a ``400`` error.

    Raises:
        ValueError: If no credential was requested.
    """
    token = request.args.get("token")
    session_id = request.args.get("session_id")
    scope = request.args.get("scope")
    authorization_details_str = request.args.get("authorization_details")
    frontend_id = request.args.get("frontend_id") or CONFIGURATION["frontend"]["default"]

    session["session_id"] = session_id

    authorization_details: List[Any] = []
    if authorization_details_str:
        try:
            authorization_details = json.loads(json.loads(urllib.parse.unquote(authorization_details_str)))
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing authorization_details JSON: {e}")
            return jsonify({"error": "Invalid authorization_details parameter"}), 400

    credential_configuration_id = None
    if scope:
        authorization_details.extend(scope2details(scope.split()))
        credential_configuration_id = scope.replace("openid", "").strip()

    if not authorization_details:
        raise ValueError(f"invalid authentication. Session ID: {session_id}")

    credentials_requested = requested_credential_ids(
        (d for d in authorization_details if isinstance(d, dict)), resolve_vct=vct2id
    )

    session_manager.add_session(
        session_id=session_id,
        jws_token=token,
        scope=credential_configuration_id,
        authorization_details=authorization_details,
        credentials_requested=credentials_requested,
        frontend_id=frontend_id,
    )

    pid_auth, country_selection = _auth_methods(credentials_requested)

    if pid_auth and not country_selection:
        return redirect(f"{CONFIGURATION['service_url']}/oid4vp")
    if country_selection and not pid_auth:
        return redirect(f"{CONFIGURATION['service_url']}/dynamic/")

    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_auth_method",
        data_payload={
            "pid_auth": pid_auth,
            "country_selection": country_selection,
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "session_id": session_id,
        },
    )


@oidc.route("/pid_authorization")
def pid_authorization_get() -> HandlerResult:
    """Checks whether the verifier has received the PID presentation.

    Returns:
        ``200`` once the presentation is available, ``500`` otherwise.

    Raises:
        ValueError: If ``presentation_id`` is missing or malformed.
    """
    presentation_id = validate_presentation_id(request.args.get("presentation_id"))
    response = fetch_presentation_result(presentation_result_url(presentation_id))
    if response.status_code != 200:
        return jsonify({"error": str(response.status_code)}), 500
    return jsonify({"message": {"message": "Sucess"}}), 200


@oidc.route("/credential", methods=["POST"])
def credential() -> HandlerResult:
    """OpenID4VCI credential endpoint.

    Returns:
        ``200`` with the credential(s), ``202`` with a ``transaction_id``
        for deferred issuance, or an error response.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return make_response(jsonify({"error": "invalid_request"}), 401)
    if not auth_header.lower().startswith(("bearer ", "dpop ")):
        return make_response(jsonify({"error": "invalid_token"}), 401)
    bearer_token = _bearer_token(auth_header)
    if bearer_token is None:
        return make_response(jsonify({"error": "invalid_token"}), 401)

    credential_request = _read_credential_request("invalid_credential_request")
    if isinstance(credential_request, Response):
        return credential_request

    introspection = verify_introspection(bearer_token=bearer_token)
    if not _is_introspection_success(introspection):
        return introspection
    session_id, wia_client_status = introspection

    validated_request = verify_credential_request(credential_request)
    if isinstance(validated_request, tuple):
        return validated_request

    logger.info(f", Session ID: {session_id}, Credential Request, Payload: {validated_request}")

    response = _issue(validated_request, session_id, wia_client_status)
    _add_notification_id(session_id, response)

    if response.get("error", "Pending") != "Pending":
        logger.error(f", Session ID: {session_id}, Credential response with error, Payload: {response}")
        return jsonify(response), 400

    is_deferred = (
        response.get("error") == "Pending"
        or validated_request.get("credential_configuration_id") == DEFERRED_ONLY_CONFIGURATION
    )
    if is_deferred:
        transaction_id = str(uuid.uuid4())
        session_manager.add_transaction_id(
            session_id=session_id, transaction_id=transaction_id, credential_request=validated_request
        )
        response = {"transaction_id": transaction_id, "interval": DEFERRED_INTERVAL_SECONDS}

    return _finish(session_id, response, is_deferred, validated_request)


@oidc.route("/admin/sessions/client_status", methods=["GET"])
@require_api_key
def get_all_sessions_client_status() -> HandlerResult:
    """Returns the client_status of every active session that has one.

    Requires the ``X-Api-Key`` header (``backend_api_key``).

    Returns:
        ``({session_id: client_status}, 200)``.
    """
    return jsonify(session_manager.get_all_client_statuses()), 200


@oidc.route("/notification", methods=["POST"])
def notification() -> HandlerResult:
    """OpenID4VCI notification endpoint.

    Returns:
        ``204`` on success, ``401`` for authorization errors.
    """
    notification_request = request.get_json()
    logger.info(f", Started Notification Request, Payload: {notification_request}")

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization header is missing"}), 401
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header must be a Bearer token"}), 401
    bearer_token = _bearer_token(auth_header)
    if bearer_token is None:
        return jsonify({"error": "Invalid Authorization header format"}), 401

    introspection = verify_introspection(bearer_token=bearer_token)
    if not _is_introspection_success(introspection):
        return introspection
    session_id, _ = introspection

    logger.info(f", Session ID: {session_id}, Notification Request, Payload: {notification_request}")
    return make_response("", 204)


@oidc.route("/nonce", methods=["POST"])
def nonce() -> HandlerResult:
    """OpenID4VCI nonce endpoint; also purges expired in-memory data.

    Returns:
        ``({"c_nonce": ...}, 200)`` with ``DPoP-Nonce`` and no-store headers.
    """
    clear_par()
    c_nonce = create_c_nonce()
    response = jsonify({"c_nonce": c_nonce})
    response.headers["Cache-Control"] = "no-store"
    response.headers["DPoP-Nonce"] = c_nonce
    return response, 200


@oidc.route("/deferred_credential", methods=["POST"])
def deferred_credential() -> HandlerResult:
    """OpenID4VCI deferred credential endpoint.

    Returns:
        ``200`` with the credential(s), ``202`` while still pending, or an
        error response.
    """
    deferred_request = _read_credential_request("Invalid JWT credential request")
    if isinstance(deferred_request, Response):
        return deferred_request

    if "transaction_id" not in deferred_request:
        return jsonify({"error": "invalid_transaction_id"}), 401

    deferred_transaction_id = deferred_request["transaction_id"]
    try:
        uuid.UUID(deferred_transaction_id, version=4)
    except (ValueError, AttributeError):
        return jsonify({"error": "invalid_transaction_id_format"}), 401

    logger.info(f", Started Deferred Request, Transaction ID: {deferred_transaction_id}")

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Authorization header is missing"}), 401
    bearer_token = _bearer_token(auth_header)
    if bearer_token is None:
        return jsonify({"error": "Invalid Authorization header format"}), 401

    introspection = verify_introspection(bearer_token=bearer_token)
    if not _is_introspection_success(introspection):
        return introspection
    session_id, wia_client_status = introspection

    logger.info(f", Session ID: {session_id}, Deferred Request, Payload: {deferred_request}")

    current_session = session_manager.get_session(session_id=session_id)
    if deferred_transaction_id not in current_session.transaction_id:
        return (
            jsonify({"error": f"Transaction ID '{deferred_transaction_id}' is not associated with this session."}),
            400,
        )

    validated_request = verify_credential_request(current_session.transaction_id[deferred_transaction_id])
    if isinstance(validated_request, tuple):
        return validated_request

    response = _issue(validated_request, session_id, wia_client_status)

    is_deferred = response.get("error") == "Pending"
    if "error" in response and not is_deferred:
        logger.error(f", Session ID: {session_id}, Credential response with error, Payload: {response}")
        return jsonify(response), 400

    if is_deferred:
        response = {"transaction_id": deferred_transaction_id, "interval": DEFERRED_INTERVAL_SECONDS}
    else:
        _add_notification_id(session_id, response)

    logger.info(f", Session ID: {session_id}, Deferred credential response, Payload: {response}")

    encryption_request = (
        {**validated_request, "credential_response_encryption": deferred_request["credential_response_encryption"]}
        if "credential_response_encryption" in deferred_request
        else {}
    )
    return _finish(session_id, response, is_deferred, encryption_request)


def _offer_choice_filter(cid: str, cfg: Dict[str, Any]) -> bool:
    """Keeps credentials issuable through one of the configured auth methods.

    Args:
        cid: Configuration id.
        cfg: Configuration (unused).

    Returns:
        ``True`` if ``cid`` is in ``PID_login`` or ``country_selection``.
    """
    methods = CONFIGURATION["credential_auth_methods"]
    return cid in methods["PID_login"] or cid in methods["country_selection"]


@oidc.route("credential_offer_choice", methods=["GET"])
def credential_offer() -> str:
    """Shows the credential selection page for building a credential offer.

    Returns:
        The frontend POST-redirect page.
    """
    frontend_id = request.args.get("frontend_id")
    session["frontend_id"] = frontend_id

    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_credential_offer",
        data_payload={
            "cred": credential_display_names(_offer_choice_filter),
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "credential_offer_URI": CONFIGURATION["credential_offer_scheme"],
        },
    )


@oidc.route("/logs", methods=["GET"])
@require_api_key
def get_logs_by_session() -> HandlerResult:
    """Returns the backend / authorization server log lines of a session.

    Requires the ``X-Api-Key`` header (``backend_api_key``).

    Returns:
        ``{session_id, count, successful, logs}`` or ``400``.
    """
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "Missing required parameter: session_id"}), 400

    log_files = [CONFIGURATION["logging"]["backend_path"]]
    if "authorization_server_path" in CONFIGURATION["logging"]:
        log_files.append(CONFIGURATION["logging"]["authorization_server_path"])

    matches: List[str] = []
    seen_lines = set()
    for log_file in log_files:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    if session_id not in line:
                        continue
                    stripped_line = _ANSI_ESCAPE.sub("", line).strip()
                    if stripped_line not in seen_lines:
                        seen_lines.add(stripped_line)
                        matches.append(stripped_line)
        except FileNotFoundError:
            continue

    return jsonify(
        {
            "session_id": session_id,
            "count": len(matches),
            "successful": any("Credential Issuance Successful" in line for line in matches),
            "logs": matches,
        }
    )


@oidc.route("/credential_offer2", methods=["GET"])
def credentialOffer2() -> Response:
    """Creates an authorization code credential offer and its QR code.

    Returns:
        ``{"base64_img": <png base64>, "session_id": ...}``.
    """
    session_id = generate_unique_id()
    configuration_id = request.args.get("credential_configuration_id", "eu.europa.ec.eudi.pid_mdoc")

    offer = authorization_code_offer(frontend_url(), [configuration_id], session_id)
    uri = credential_offer_uri(CONFIGURATION["credential_offer_scheme"], offer)

    logger.info(f", Session ID: {session_id}, Credential offer successfully generated, uri: {uri}")
    return jsonify({"base64_img": qr_png_base64(uri), "session_id": session_id})


@oidc.route("/credential_offer_create", methods=["GET"])
def credentialOfferCreate() -> HandlerResult:
    """Creates an authorization code credential offer.

    Returns:
        The offer, or ``400`` when ``credential_configuration_id`` is missing.
    """
    configuration_id = request.args.get("credential_configuration_id")
    if not configuration_id:
        return {
            "error": "invalid_request",
            "error_description": "Missing required parameter: credential_configuration_id",
        }, 400
    return authorization_code_offer(frontend_url(), [configuration_id], generate_unique_id())


@oidc.route("/credential_offer", methods=["GET", "POST"])
def credentialOffer() -> HandlerResult:
    """Handles the credential offer form.

    Pre-authorized offers continue in :mod:`app.routes.preauth`;
    authorization code offers are rendered as a QR code here.

    Returns:
        A redirect, the frontend POST-redirect page, or ``400``.
    """
    credentials_supported = oidc_metadata["credential_configurations_supported"]
    form_keys = list(request.form.keys())

    if "proceed" not in form_keys:
        query = f"?frontend_id={session['frontend_id']}" if "frontend_id" in session else ""
        return redirect(f"{CONFIGURATION['service_url']}/credential_offer_choice{query}")

    auth_choice = request.form.get("Authorization Code Grant")
    credential_offer_URI = request.form.get("credential_offer_URI")
    excluded = {"proceed", "credential_offer_URI", "Authorization Code Grant"}
    credentials_id = [k for k in form_keys if k not in excluded]

    if not all(credential in credentials_supported for credential in credentials_id):
        return jsonify({"error": "invalid_request", "error_description": "Unsupported credential"}), 400

    session["credentials_id"] = credentials_id

    if auth_choice == "pre_auth_code":
        session["credential_offer_URI"] = credential_offer_URI
        return redirect(url_for("preauth.preauthRed", credentials_id=json.dumps(credentials_id)))

    frontend_id = session.get("frontend_id")
    offer = authorization_code_offer(frontend_url(frontend_id), credentials_id, generate_unique_id())

    credential_offer_references[str(uuid.uuid4())] = {
        "credential_offer": offer,
        "expires": datetime.now() + timedelta(minutes=CONFIGURATION["expiry"]["form"]),
    }

    uri = credential_offer_uri(credential_offer_URI, offer)

    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_credential_offer_qr_code",
        data_payload={
            "wallet_dev": f"{CONFIGURATION['wallet_tester_url']}/credential_offer",
            "credential_offer": offer,
            "url_data": uri,
            "qrcode": qr_data_uri(uri),
        },
    )


@oidc.route("/credential-offer-reference/<string:reference_id>", methods=["GET"])
def offer_reference(reference_id: str) -> HandlerResult:
    """Serves a credential offer by reference (``credential_offer_uri``).

    Args:
        reference_id: Offer reference id.

    Returns:
        The offer, or ``404`` when unknown or expired.
    """
    entry = credential_offer_references.get(reference_id)
    if entry is None:
        return jsonify({"error": "not_found"}), 404
    return entry["credential_offer"]


@oidc.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e: werkzeug.exceptions.BadRequest) -> Tuple[str, int]:
    """Blueprint handler for ``400 Bad Request``.

    Args:
        e: The exception.

    Returns:
        ``("bad request!", 400)``.
    """
    return "bad request!", 400

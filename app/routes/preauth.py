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
"""Pre-authorized code flow (test support).

The libraries used do not support pre-authorization natively; these routes
obtain a pre-authorized code from the authorization server, collect the
user attributes and produce a credential offer for testing purposes.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Tuple, Union

import jwt
from flask import Blueprint, Response, jsonify, request, session

from app.core.config import CONFIGURATION
from app.core.state import session_manager
from app.services.attributes import getAttributesForm, getAttributesForm2, optional_only, requested_credential_ids
from app.services.auth_server import generate_preauth_code
from app.services.credential_offer import credential_offer_uri, pre_authorized_offer
from app.services.presentation import form_formatter, presentation_formatter
from app.core.errors import CertificateVerificationError
from app.services.trust import CREDENTIAL_OFFER_REQUEST_CONTEXT, trust_context, trust_use_case, verify_jwt_with_x5c
from app.utils.forms import parse_form
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload
from app.utils.ids import generate_unique_id
from app.utils.qr import qr_data_uri

preauth = Blueprint("preauth", __name__, url_prefix="/")
logger = logging.getLogger(__name__)

AGE_VERIFICATION_SCOPES = (
    "eu.europa.ec.eudi.age_verification_mdoc",
    "eu.europa.ec.eudi.age_verification_mdoc_passport",
)


def _authorization_details(credential_ids: list) -> list:
    """Builds ``openid_credential`` authorization details.

    Args:
        credential_ids: Credential configuration ids.

    Returns:
        One authorization detail per id.
    """
    return [{"type": "openid_credential", "credential_configuration_id": cid} for cid in credential_ids]


def request_preauth_token(scope: str) -> str:
    """Obtains a pre-authorized code and creates the matching issuance session.

    Args:
        scope: Space separated credential configuration ids.

    Returns:
        The new session id (assigned by the authorization server).
    """
    response = generate_preauth_code(scope)
    session_id = response.get("session_id")
    session_manager.add_session(
        session_id=session_id,
        pre_authorized_code=response.get("preauth_code"),
        scope=scope,
        tx_code=response.get("tx_code"),
        country="AV" if scope in AGE_VERIFICATION_SCOPES else "FC",
    )
    return session_id


@preauth.route("/preauth", methods=["GET"])
def preauthRed() -> str:
    """Starts a pre-authorized flow for the credentials chosen in the offer form.

    Query parameters:
        credentials_id: JSON list of credential configuration ids.

    Returns:
        The attribute form page.
    """
    credential_list = json.loads(request.args.get("credentials_id"))
    session_id = request_preauth_token(scope=" ".join(credential_list))
    session["session_id"] = session_id

    authorization_details = _authorization_details(credential_list)
    session_manager.update_authorization_details(session_id=session_id, authorization_details=authorization_details)
    session_manager.update_frontend_id(
        session_id=session_id, frontend_id=session.get("frontend_id") or CONFIGURATION["frontend"]["default"]
    )

    credentials_requested = requested_credential_ids(authorization_details)
    session_manager.update_credentials_requested(session_id=session_id, credentials_requested=credentials_requested)

    mandatory_attributes = getAttributesForm(credentials_requested)
    optional_attributes = optional_only(getAttributesForm2(credentials_requested), mandatory_attributes)

    current_session = session_manager.get_session(session_id=session_id)
    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_form",
        data_payload={
            "mandatory_attributes": mandatory_attributes,
            "optional_attributes": optional_attributes,
            "redirect_url": f"{CONFIGURATION['service_url']}/preauth_form",
            "session_id": session_id,
        },
    )


@preauth.route("/preauth_form", methods=["GET", "POST"])
def preauth_form() -> str:
    """Receives the attribute form and shows the consent page.

    Returns:
        The consent page.
    """
    form_data = parse_form(request.form)
    logger.info(f"form_data: {form_data}")

    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)
    logger.info(f"session_id: {session_id}")

    form_data.pop("proceed")
    cleaned_data = form_formatter(form_data, issuing_country=current_session.country)
    session_manager.update_user_data(session_id=session_id, user_data=cleaned_data)

    presentation_data = presentation_formatter(
        cleaned_data=cleaned_data,
        credentials_requested=current_session.credentials_requested,
        country=current_session.country,
    )
    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_authorization",
        data_payload={
            "presentation_data": presentation_data,
            "redirect_url": f"{CONFIGURATION['service_url']}/form_authorize_generate",
            "session_id": session_id,
        },
    )


@preauth.route("/form_authorize_generate", methods=["GET", "POST"])
def form_authorize_generate() -> str:
    """Generates the credential offer after the user consented.

    Returns:
        The credential offer QR code page.
    """
    current_session = session_manager.get_session(request.form.to_dict()["user_id"])
    return generate_offer(current_session.user_data)


def generate_offer(data: Dict[str, Any]) -> str:
    """Shows the pre-authorized credential offer of the current session.

    Args:
        data: User data (unused; kept for API compatibility).

    Returns:
        The frontend page with the offer, its URI and QR code.
    """
    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)
    frontend_id = session.get("frontend_id")

    offer = pre_authorized_offer(
        credential_issuer=frontend_url(frontend_id),
        credential_configuration_ids=current_session.credentials_requested,
        issuer_state=session_id,
        pre_authorized_code=current_session.pre_authorized_code,
    )
    uri = credential_offer_uri(session["credential_offer_URI"], offer)

    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_credential_offer_qr_code",
        data_payload={
            "wallet_dev": f"{CONFIGURATION['wallet_tester_url']}/redirect_preauth",
            "credential_offer": offer,
            "url_data": uri,
            "qrcode": qr_data_uri(uri, scale=2),
            "tx_code": current_session.tx_code,
            "code": generate_unique_id(),
        },
    )


@preauth.route("/credentialOfferReq2", methods=["POST"])
def credentialOfferReq2() -> Union[Dict[str, Any], Tuple[Response, int]]:
    """Creates a pre-authorized offer (with embedded ``tx_code``) from a signed request.

    The ``request`` JWT must carry an ``x5c`` chain trusted by the trust
    validator or the local trusted CAs (see :mod:`app.services.trust`); its
    signature (and ``exp``, when present) is verified.

    Form parameters:
        request: JWT whose payload has ``credentials: [{credential_configuration_id, data}]``.

    Returns:
        The credential offer, ``400`` when ``request`` is missing or malformed,
        or ``401`` when the JWT is not signed by a trusted certificate.
    """
    json_token = request.form.get("request")
    if not json_token:
        return jsonify({"error": "invalid_request", "error_description": "Missing request JWT"}), 400

    try:
        json_payload = verify_jwt_with_x5c(
            json_token,
            verification_context=trust_context("credential_offer_request", CREDENTIAL_OFFER_REQUEST_CONTEXT),
            use_case=trust_use_case("credential_offer_request"),
        )
    except CertificateVerificationError as e:
        logger.warning(f"credentialOfferReq2 rejected: untrusted signer: {e}")
        return jsonify({"error": "invalid_request", "error_description": "Untrusted request signer"}), 401
    except jwt.InvalidTokenError as e:
        logger.warning(f"credentialOfferReq2 rejected: invalid JWT: {e}")
        return jsonify({"error": "invalid_request", "error_description": "Invalid request JWT signature"}), 401
    except ValueError as e:
        logger.warning(f"credentialOfferReq2 rejected: malformed JWT: {e}")
        return jsonify({"error": "invalid_request", "error_description": str(e)}), 400

    credentials = json_payload["credentials"]
    credential_ids = list(dict.fromkeys(c["credential_configuration_id"] for c in credentials))

    session_id = request_preauth_token(scope=" ".join(credential_ids))
    session_manager.update_authorization_details(
        session_id=session_id,
        authorization_details=_authorization_details([c["credential_configuration_id"] for c in credentials]),
    )
    session_manager.update_user_data(session_id=session_id, user_data=credentials[0]["data"])

    current_session = session_manager.get_session(session_id=session_id)
    return pre_authorized_offer(
        credential_issuer=frontend_url(),
        credential_configuration_ids=credential_ids,
        issuer_state=session_id,
        pre_authorized_code=current_session.pre_authorized_code,
        tx_code_value=current_session.tx_code,
    )

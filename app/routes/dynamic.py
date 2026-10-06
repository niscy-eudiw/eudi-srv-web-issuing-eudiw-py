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
"""``/dynamic`` blueprint: country selection, user attribute collection and
the internal credential creation endpoint.

The Dynamic Issuer Web service is a component of the Dynamic Provider
backend. Its main goal is to issue credentials in cbor/mdoc (ISO 18013-5
mdoc) and SD-JWT format.
"""

from __future__ import annotations

import logging
from http import HTTPStatus
from typing import Any, Dict, Tuple, Union
from uuid import uuid4

from flask import Blueprint, Response, redirect, request, session

from app.core.config import CONFIGURATION
from app.core.constants import ConfService as cfgserv
from app.core.state import session_manager
from app.repositories.session_store import Session
from app.services.attributes import getAttributesForm, getAttributesForm2, optional_only
from app.services.countries import (
    collect_user_data,
    country_config,
    exchange_authorization_code,
    generate_connector_authorization_url,
    is_form_country,
    openid_authorization_url,
)
from app.services.presentation import form_formatter, presentation_formatter
from app.utils.forms import parse_form
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload, url_get
from app.utils.validation import validate_mandatory_args

dynamic = Blueprint("dynamic", __name__, url_prefix="/dynamic")

logger = logging.getLogger(__name__)

AGE_VERIFICATION_PASSPORT = "eu.europa.ec.eudi.age_verification_mdoc_passport"

HandlerResult = Union[Response, str, Tuple[Any, int]]


def _current_session() -> Tuple[str, Session]:
    """Returns the issuance session bound to the browser session.

    Returns:
        ``(session_id, session)``.
    """
    session_id = session["session_id"]
    return session_id, session_manager.get_session(session_id=session_id)


def _redirect_to_user_verification(session_id: str, jws_token: str) -> Response:
    """Redirects back to the authorization server's user verification endpoint.

    Args:
        session_id: Issuance session (sent as ``username``).
        jws_token: Session JWS token.

    Returns:
        The redirect response.
    """
    return redirect(
        url_get(
            CONFIGURATION["authorization_server"]["user_verify_endpoint"],
            {"token": jws_token, "username": session_id},
        )
    )


def _display_authorization(current_session: Session, presentation_data: Dict[str, Any]) -> str:
    """Shows the consent page before redirecting back to the wallet flow.

    Args:
        current_session: Issuance session.
        presentation_data: See :func:`presentation_formatter`.

    Returns:
        The frontend POST-redirect page.
    """
    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_authorization",
        data_payload={
            "presentation_data": presentation_data,
            "redirect_url": f"{CONFIGURATION['service_url']}/dynamic/redirect_wallet",
            "session_id": current_session.session_id,
        },
    )


@dynamic.route("/", methods=["GET", "POST"])
def Supported_Countries() -> HandlerResult:
    """Initial page: lets the user choose the country that authenticates them.

    Passport age verification skips the choice; a single eligible country
    is selected automatically.

    Returns:
        A redirect or the country selection page.
    """
    session_id, current_session = _current_session()

    if AGE_VERIFICATION_PASSPORT in current_session.credentials_requested:
        session_manager.update_user_data(session_id=session_id, user_data={"age_over_18": True})
        session_manager.update_country(session_id=session_id, country="AV")
        return _redirect_to_user_verification(session_id, current_session.jws_token)

    display_countries = {
        str(country): str(config["name"])
        for country, config in CONFIGURATION["countries"].items()
        if all(c in config["supported_credential_ids"] for c in current_session.credentials_requested)
    }

    if len(display_countries) == 1:
        country = next(iter(display_countries))
        logger.info(f", Session ID: {session_id}, Authorization selection, Type: {country}")
        return dynamic_R1(country)

    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_countries",
        data_payload={
            "countries": display_countries,
            "authorization_details": current_session.authorization_details,
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "session_id": session_id,
        },
    )


@dynamic.route("/country_selected", methods=["GET", "POST"])
def country_selected() -> HandlerResult:
    """Handles the country chosen on the selection page.

    Returns:
        See :func:`dynamic_R1`.
    """
    form_country = request.form.get("country")
    logger.info(f", Session ID: {session['session_id']}, Authorization selection, Type: {form_country}")
    return dynamic_R1(form_country)


def dynamic_R1(country: str) -> HandlerResult:
    """Sends the user to the attribute form or the country identity provider.

    Args:
        country: Selected country.

    Returns:
        The form page (form countries) or a redirect to the IdP.
    """
    session_id = session["session_id"]
    session_manager.update_country(session_id=session_id, country=country)
    current_session = session_manager.get_session(session_id=session_id)

    if is_form_country(country):
        mandatory_attributes = getAttributesForm(current_session.credentials_requested)
        if "user_pseudonym" in mandatory_attributes:
            mandatory_attributes["user_pseudonym"] = {"type": "string", "filled_value": str(uuid4())}

        optional_attributes = optional_only(
            getAttributesForm2(current_session.credentials_requested), mandatory_attributes
        )
        return post_redirect_with_payload(
            target_url=f"{frontend_url(current_session.frontend_id)}/display_form",
            data_payload={
                "mandatory_attributes": mandatory_attributes,
                "optional_attributes": optional_attributes,
                "redirect_url": f"{CONFIGURATION['service_url']}/dynamic/form",
                "session_id": session_id,
            },
        )

    match country_config(country)["connection_type"]:
        case "oauth":
            state = str(uuid4())
            session["oauth_state"] = state
            return redirect(
                generate_connector_authorization_url(
                    oauth_data=country_config(country)["auth"],
                    country=country,
                    credentials_requested=current_session.credentials_requested,
                    state=state,
                )
            )
        case "openid":
            return redirect(openid_authorization_url(country, state=current_session.session_id))
        case other:
            return f"Unsupported connection type: {other}", HTTPStatus.BAD_REQUEST


@dynamic.route("/redirect", methods=["GET", "POST"])
def red() -> HandlerResult:
    """Receives the authorization code from a country identity provider.

    GET parameters:
        code (mandatory): Authorization code to retrieve the attributes
            consented by the user.

    Returns:
        The consent page.

    Raises:
        ValueError: If ``code`` is missing or the IdP exchange fails.
    """
    session_id, current_session = _current_session()

    valid, missing = validate_mandatory_args(request.args, ["code"])
    if not valid:
        raise ValueError(f"Missing mandatory IdP fields: {missing}")

    access_token = exchange_authorization_code(current_session.country, request.args.get("code"))
    session["access_token"] = access_token

    data = collect_user_data(country=current_session.country, session_id=session_id, access_token=access_token)

    presentation_data = presentation_formatter(
        cleaned_data=data,
        credentials_requested=current_session.credentials_requested,
        country=current_session.country,
        include_optional=False,
    )
    return _display_authorization(current_session, presentation_data)


@dynamic.route("/auth_method", methods=["GET", "POST"])
def auth() -> HandlerResult:
    """Handles the authentication method chosen by the user.

    Returns:
        A redirect to PID login (``link1``) or country selection (``link2``).

    Raises:
        ValueError: If the user cancelled.
    """
    session_id = session["session_id"]
    if "Cancelled" in request.form.keys():
        raise ValueError(f"User canceled authentication. Session ID: {session_id}")

    match request.form.get("optionsRadios"):
        case "link1":
            return redirect(f"{CONFIGURATION['service_url']}/oid4vp")
        case "link2":
            return redirect(f"{CONFIGURATION['service_url']}/dynamic/")
        case _:
            return "Invalid authentication method", HTTPStatus.BAD_REQUEST


@dynamic.route("/form", methods=["GET", "POST"])
def Dynamic_form() -> HandlerResult:
    """Receives the attribute form filled in by the user.

    Returns:
        The consent page, or ``400`` for a GET (the form is only POSTed).
    """
    session_id, current_session = _current_session()

    if request.method == "GET":
        # The form is only ever POSTed by the frontend.
        return "Error 101: " + cfgserv.error_list["101"] + "\n", HTTPStatus.BAD_REQUEST

    form_data = parse_form(request.form)
    form_data.pop("proceed")

    cleaned_data = form_formatter(form_data, issuing_country=current_session.country)
    session_manager.update_user_data(session_id=session_id, user_data=cleaned_data)

    presentation_data = presentation_formatter(
        cleaned_data=cleaned_data,
        credentials_requested=current_session.credentials_requested,
        country=current_session.country,
    )
    return _display_authorization(current_session, presentation_data)


@dynamic.route("/redirect_wallet", methods=["GET", "POST"])
def redirect_wallet() -> Response:
    """Returns the user to the authorization server after consent.

    Returns:
        The redirect response.
    """
    session_id, current_session = _current_session()
    return _redirect_to_user_verification(session_id, current_session.jws_token)

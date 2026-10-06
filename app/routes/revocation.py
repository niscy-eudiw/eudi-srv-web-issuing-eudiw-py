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
"""``/revocation`` blueprint: lets a user revoke credentials they hold.

The user selects credential types, presents those credentials from their
wallet over OpenID4VP, and the status list entries found in them are
flipped to *revoked*.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List

from flask import Blueprint, abort, jsonify, request, session

from app.core.config import CONFIGURATION
from app.core.state import oidc_metadata
from app.repositories.offer_store import revocation_requests
from app.services.attributes import credential_display_names
from app.services.oid4vp import (
    build_dcql_query,
    fetch_presentation_result,
    result_url_from_request,
    start_presentation,
)
from app.services.revocation_status import (
    describe_status_list,
    get_status_mdoc,
    get_status_sdjwt,
    set_token_status,
)
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload
from app.utils.ids import generate_unique_id
from app.utils.qr import qr_data_uri

revocation = Blueprint("revocation", __name__, url_prefix="/revocation")

logger = logging.getLogger(__name__)

#: mdoc configurations that cannot be revoked by the user.
NON_REVOCABLE_MDOC_SCOPES = (
    "eu.europa.ec.eudi.age_verification_mdoc_passport",
    "eu.europa.ec.eudi.age_verification_mdoc",
)
FORMATS = ("dc+sd-jwt", "mso_mdoc")


def _revocable(cid: str, cfg: Dict[str, Any]) -> bool:
    """Filters out credentials that cannot be revoked.

    Args:
        cid: Configuration id (unused).
        cfg: Configuration.

    Returns:
        ``False`` for age verification mdocs.
    """
    return not (cfg["format"] == "mso_mdoc" and cfg["scope"] in NON_REVOCABLE_MDOC_SCOPES)


# TODO finish revocation pages.
@revocation.route("revocation_choice", methods=["GET"])
def revocation_choice() -> str:
    """Page for selecting the credential types to revoke.

    Returns:
        The frontend selection page.
    """
    return post_redirect_with_payload(
        target_url=f"{frontend_url()}/display_revocation_choice",
        data_payload={
            "cred": credential_display_names(_revocable),
            "redirect_url": f"{CONFIGURATION['service_url']}/revocation/oid4vp_call",
        },
    )


@revocation.route("oid4vp_call", methods=["GET", "POST"])
def oid4vp_call() -> str:
    """Requests a presentation of the selected credentials.

    Returns:
        The frontend page showing the deeplink and QR code.
    """
    selected = [key for key in request.form.keys() if key != "proceed"]
    session_id = str(uuid.uuid4())
    session["session_id"] = session_id

    dcql_query, formats = build_dcql_query(
        selected, oidc_metadata["credential_configurations_supported"], sdjwt_intent_to_retain=False
    )
    session.update(formats)  # query_id -> format, read back in oid4vp_get

    response_redirect_uri = (
        f"{CONFIGURATION['service_url']}/revocation/getoid4vp?response_code={{RESPONSE_CODE}}&session_id={session_id}"
    )
    presentation = start_presentation(dcql_query, response_redirect_uri)
    # The revocation flow has no SessionManager session; keep the same-device
    # transaction id in the browser session for oid4vp_get.
    session["oid4vp_transaction_id"] = presentation.same_device["transaction_id"]

    return post_redirect_with_payload(
        target_url=f"{frontend_url()}/display_revocation_qr_code",
        data_payload={
            "url_data": presentation.deeplink_url,
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "qrcode": qr_data_uri(presentation.qr_code_url),
            "presentation_id": presentation.cross_device["transaction_id"],
        },
    )


def _statuses_by_format(vp_token: Dict[str, List[str]]) -> Dict[str, List[Dict[str, Any]]]:
    """Extracts the status claims of every presented credential.

    Args:
        vp_token: ``{query_id: [credential, ...]}`` from the verifier.

    Returns:
        ``{format: [status, ...]}``.
    """
    statuses: Dict[str, List[Dict[str, Any]]] = {fmt: [] for fmt in FORMATS}
    for query_id, presented in vp_token.items():
        match session[query_id]:
            case "mso_mdoc":
                for credential in presented:
                    status = get_status_mdoc(credential)
                    statuses["mso_mdoc"].extend(status if isinstance(status, list) else [status])
            case "dc+sd-jwt":
                statuses["dc+sd-jwt"].extend(get_status_sdjwt(credential) for credential in presented)
    return statuses


@revocation.route("getoid4vp", methods=["GET", "POST"])
def oid4vp_get() -> Any:
    """Receives the presentation and asks the user to confirm revocation.

    Returns:
        The confirmation page, or ``400`` on missing parameters / verifier errors.
    """
    session_id = session.get("session_id")
    same_device = "response_code" in request.args and "session_id" in request.args
    logger.info(f", Session ID: {session_id}, oid4vp flow: {'same_device' if same_device else 'cross_device'}")

    url = result_url_from_request(request.args, session.get("oid4vp_transaction_id"))
    if url is None:
        return jsonify({"error": "Missing required parameters"}), 400

    response = fetch_presentation_result(url)
    if response.status_code != 200:
        return jsonify({"error": str(response.status_code)}), 400

    statuses = _statuses_by_format(response.json()["vp_token"])
    display_list = {
        fmt: [d for d in (describe_status_list(s) for s in fmt_statuses) if d]
        for fmt, fmt_statuses in statuses.items()
    }

    revocation_id = generate_unique_id()
    revocation_requests[revocation_id] = {
        "status_lists": statuses,
        "expires": datetime.now() + timedelta(minutes=CONFIGURATION["expiry"]["revocation_code"]),
    }

    return post_redirect_with_payload(
        target_url=f"{frontend_url()}/display_revocation_authorization",
        data_payload={
            "display_list": display_list,
            "redirect_url": f"{CONFIGURATION['service_url']}/revocation/revoke",
            "revocation_identifier": revocation_id,
            "revocation_choice_url": f"{CONFIGURATION['service_url']}/revocation/revocation_choice",
        },
    )


@revocation.route("revoke", methods=["GET", "POST"])
def revoke() -> str:
    """Revokes every status list entry of a confirmed revocation request.

    Returns:
        The success page.

    Raises:
        werkzeug.exceptions.BadRequest: If the identifier is missing.
        werkzeug.exceptions.NotFound: If it is unknown or expired.
    """
    revocation_identifier = request.form.get("revocation_identifier")
    if not revocation_identifier:
        abort(400, description="Missing revocation identifier")
    if revocation_identifier not in revocation_requests:
        abort(404, description="Invalid or expired revocation identifier")

    for statuses in revocation_requests[revocation_identifier]["status_lists"].values():
        for status in statuses:
            if "identifier_list" in status:
                identifier = status["identifier_list"]
                set_token_status("id", identifier["id"].decode("utf-8"), identifier["uri"], respect_enabled_flag=False)
            if "status_list" in status:
                pointer = status["status_list"]
                set_token_status("idx", pointer["idx"], pointer["uri"], respect_enabled_flag=False)

    revocation_requests.pop(revocation_identifier)

    return post_redirect_with_payload(
        target_url=f"{frontend_url()}/display_revocation_success",
        data_payload={"redirect_url": f"{CONFIGURATION['service_url']}/"},
    )

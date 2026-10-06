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
"""``/formatter`` blueprint: stand-alone mdoc and SD-JWT formatting API.

Both endpoints answer HTTP 200 with ``error_code`` / ``error_message`` and
the credential (empty on error).
"""

from __future__ import annotations

import logging

from flask import Blueprint, Response, request

from app.core.config import CONFIGURATION
from app.core.errors import formatter_result
from app.services.formatters import mdocFormatter, sdjwtFormatter
from app.utils.validation import validate_date_format, validate_mandatory_args

formatter = Blueprint("formatter", __name__, url_prefix="/formatter")

logger = logging.getLogger(__name__)

MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
MDL_NAMESPACE = "org.iso.18013.5.1"


@formatter.route("/cbor", methods=["POST"])
def cborformatter() -> Response:
    """Creates and signs an ISO 18013-5 mdoc.

    POST JSON parameters:
        country (mandatory): ISO 3166-1 alpha-2 country code.
        credential_metadata (mandatory): Credential configuration.
        device_publickey (mandatory): Holder device public key.
        data (mandatory): ``{namespace: {element: value}}``.
        session_id (optional): Issuance session to bind the credential to.

    Returns:
        JSON ``{error_code, error_message, mdoc}``; ``mdoc`` is the signed
        base64url mdoc (empty when ``error_code != 0``). Error codes: 401
        missing fields, 102 unsupported country, 306 invalid date.
    """
    body = request.json
    valid, _ = validate_mandatory_args(body, ["country", "credential_metadata", "device_publickey", "data"])
    if not valid:
        return formatter_result(401)

    if body["country"] not in CONFIGURATION["countries"]:
        return formatter_result(102)

    if body["credential_metadata"]["doctype"] == MDL_DOCTYPE:
        mdl_data = body["data"][MDL_NAMESPACE]
        for field in ("expiry_date", "issue_date"):
            value = mdl_data.get(field)
            if value is not None and not validate_date_format(value):
                return formatter_result(306)

    base64_mdoc = mdocFormatter(
        body["data"],
        body["credential_metadata"],
        body["country"],
        body["device_publickey"],
        body.get("session_id"),
    )
    return formatter_result(0, value=base64_mdoc)


@formatter.route("/sd-jwt", methods=["POST"])
def sd_jwtformatter() -> Response:
    """Creates and signs an SD-JWT VC.

    POST JSON parameters:
        country (mandatory): ISO 3166-1 alpha-2 country code.
        scope (mandatory): Credential scope.
        credential_metadata, data, device_publickey (mandatory): See
            :func:`app.services.formatters.sdjwtFormatter`.
        session_id (optional): Issuance session to bind the credential to.

    Returns:
        JSON ``{error_code, error_message, sd-jwt}``.
    """
    pid = request.get_json()
    sd_jwt = sdjwtFormatter(pid, pid["country"], pid["scope"], pid.get("session_id"))
    return formatter_result(0, field="sd-jwt", value=sd_jwt)

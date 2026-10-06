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
"""Client for the OpenID4VP verifier backend.

Used by the PID authentication flow (``/oid4vp``), the revocation flow and
``/pid_authorization`` to request a presentation from the wallet and fetch
the verifier's result.

Attributes:
    PRESENTATION_NONCE: Nonce sent to the verifier.

Security note:
    The nonce is a fixed value, as in the original implementation; it should
    be generated per transaction (see ``REFACTORING.md``).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

import requests

from app.core.config import CONFIGURATION
from app.utils.http import DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)

PRESENTATION_NONCE = "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
_PRESENTATION_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_JSON_HEADERS = {"Content-Type": "application/json"}


@dataclass(frozen=True)
class PresentationRequest:
    """Result of creating a cross-device and a same-device presentation request.

    Attributes:
        cross_device: Verifier response for the QR-code (cross-device) request.
        same_device: Verifier response for the same-device request.
        deeplink_url: Wallet deeplink for the same-device flow.
        qr_code_url: URL to encode in the cross-device QR code.
    """

    cross_device: Dict[str, Any]
    same_device: Dict[str, Any]
    deeplink_url: str
    qr_code_url: str


def build_dcql_query(
    credential_ids: Iterable[str],
    credentials_supported: Mapping[str, Dict[str, Any]],
    sdjwt_intent_to_retain: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Builds a DCQL query requesting every claim of the given credentials.

    Args:
        credential_ids: Credential configuration ids to request.
        credentials_supported: Issuer credential configurations.
        sdjwt_intent_to_retain: Whether SD-JWT claims carry
            ``intent_to_retain: false`` (mdoc claims always do).

    Returns:
        ``(dcql_query, {query_id: format})``.
    """
    credentials: List[Dict[str, Any]] = []
    formats: Dict[str, str] = {}

    for index, credential_id in enumerate(credential_ids):
        config = credentials_supported[credential_id]
        credential_format = config["format"]
        query_id = f"query_{index}"
        formats[query_id] = credential_format

        dcql_credential: Dict[str, Any] = {"id": query_id, "format": credential_format, "claims": []}
        match credential_format:
            case "dc+sd-jwt":
                dcql_credential["meta"] = {"vct_values": [config["vct"]]}
                with_intent = sdjwt_intent_to_retain
            case "mso_mdoc":
                dcql_credential["meta"] = {"doctype_value": config["doctype"]}
                with_intent = True
            case _:
                with_intent = True

        dcql_credential["claims"] = [
            {"path": claim["path"], "intent_to_retain": False} if with_intent else {"path": claim["path"]}
            for claim in config["credential_metadata"]["claims"]
        ]
        credentials.append(dcql_credential)

    return {"credentials": credentials}, formats


def oid4vp_verifier_requests(
    dcql_query: Dict[str, Any], response_redirect_uri: str
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Creates a cross-device and a same-device presentation request.

    Args:
        dcql_query: DCQL query.
        response_redirect_uri: Wallet response redirect template (same
            device only), containing ``{RESPONSE_CODE}``.

    Returns:
        ``(cross_device_response, same_device_response)`` verifier JSON.

    Raises:
        ValueError: If neither ``intended_use_id`` nor
            ``registration_certificate_jwt`` is configured.
        requests.RequestException: On network errors.
    """
    intended_use_id = CONFIGURATION.get("intended_use_id")
    registration_certificate = CONFIGURATION.get("registration_certificate_jwt")
    if not registration_certificate and not intended_use_id:
        raise ValueError(
            "At least one of 'intended_use_id' or 'registration_certificate_jwt' "
            "must be defined in the configuration file."
        )

    payload: Dict[str, Any] = {
        "type": "vp_token",
        "nonce": PRESENTATION_NONCE,
        "request_uri_method": "get",
        "dcql_query": dcql_query,
    }
    if registration_certificate:
        payload["registration_certificate"] = registration_certificate
    else:
        payload["intended_use_id"] = intended_use_id

    url = CONFIGURATION["dynamic_presentation_url"]
    payload_cross_device = json.dumps(payload)
    payload_same_device = json.dumps({**payload, "wallet_response_redirect_uri_template": response_redirect_uri})

    response_cross = requests.request(
        "POST", url, headers=_JSON_HEADERS, data=payload_cross_device, timeout=DEFAULT_TIMEOUT
    ).json()
    response_same = requests.request(
        "POST", url, headers=_JSON_HEADERS, data=payload_same_device, timeout=DEFAULT_TIMEOUT
    ).json()
    logger.debug(
        f"Verifier presentation requests created: cross_device={response_cross.get('transaction_id')} "
        f"same_device={response_same.get('transaction_id')}"
    )
    return response_cross, response_same


def _wallet_url(verifier_response: Mapping[str, Any]) -> str:
    """Builds the wallet invocation URL for a verifier request.

    Args:
        verifier_response: Verifier response with ``client_id`` / ``request_uri``.

    Returns:
        ``<oid4vp_scheme><verifier domain>?client_id=...&request_uri=...``.
    """
    domain = urlparse(CONFIGURATION["dynamic_presentation_url"]).netloc
    return (
        f"{CONFIGURATION['oid4vp_scheme']}{domain}"
        f"?client_id={verifier_response['client_id']}&request_uri={verifier_response['request_uri']}"
    )


def start_presentation(dcql_query: Dict[str, Any], response_redirect_uri: str) -> PresentationRequest:
    """Creates the verifier requests and the wallet URLs for both flows.

    Args:
        dcql_query: DCQL query.
        response_redirect_uri: Same-device wallet response redirect template.

    Returns:
        The :class:`PresentationRequest`.
    """
    cross, same = oid4vp_verifier_requests(dcql_query, response_redirect_uri)
    return PresentationRequest(
        cross_device=cross,
        same_device=same,
        deeplink_url=_wallet_url(same),
        qr_code_url=_wallet_url(cross),
    )


def validate_presentation_id(presentation_id: Optional[str]) -> str:
    """Validates a verifier presentation (transaction) id from user input.

    Args:
        presentation_id: Candidate id.

    Returns:
        The id.

    Raises:
        ValueError: If missing or containing unexpected characters.
    """
    if not presentation_id:
        raise ValueError("Presentation id is required")
    if not _PRESENTATION_ID_RE.match(presentation_id):
        raise ValueError("Invalid Presentation id format")
    return presentation_id


def presentation_result_url(presentation_id: str, response_code: Optional[str] = None) -> str:
    """Builds the verifier URL from which a presentation result is fetched.

    Args:
        presentation_id: Verifier transaction id.
        response_code: Same-device response code, if any.

    Returns:
        The result URL.
    """
    base_url = CONFIGURATION["dynamic_presentation_url"].rstrip("/")
    url = f"{base_url}/{presentation_id}?nonce={PRESENTATION_NONCE}"
    return f"{url}&response_code={response_code}" if response_code is not None else url


def result_url_from_request(args: Mapping[str, str], same_device_transaction_id: Optional[str]) -> Optional[str]:
    """Chooses the same- or cross-device result URL from callback arguments.

    Args:
        args: Request query arguments.
        same_device_transaction_id: Transaction id stored for the
            same-device request.

    Returns:
        The result URL, or ``None`` when neither ``response_code`` +
        ``session_id`` nor ``presentation_id`` is present.

    Raises:
        ValueError: If ``presentation_id`` is present but invalid.
    """
    if "response_code" in args and "session_id" in args:
        return presentation_result_url(same_device_transaction_id, args.get("response_code"))
    if "presentation_id" in args:
        return presentation_result_url(validate_presentation_id(args.get("presentation_id")))
    return None


def fetch_presentation_result(url: str) -> requests.Response:
    """GETs a presentation result from the verifier.

    Args:
        url: Result URL (see :func:`presentation_result_url`).

    Returns:
        The HTTP response.

    Raises:
        requests.RequestException: On network errors.
    """
    response = requests.request("GET", url, headers=_JSON_HEADERS, timeout=DEFAULT_TIMEOUT)
    logger.debug(f"Verifier presentation result fetched: HTTP {response.status_code}")
    return response

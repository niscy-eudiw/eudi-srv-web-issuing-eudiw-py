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
"""Client for the token status list (revocation) service.

* :func:`reserve_status_entry` reserves a status list entry for a credential
  being issued (``/token_status_list/take``).
* :func:`set_token_status` flips the status bit of an entry
  (``/token_status_list/set``).
* :func:`get_status_sdjwt` / :func:`get_status_mdoc` read the ``status``
  claim from presented credentials.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import cbor2
import requests

from app.core.config import CONFIGURATION
from app.services.trust import verify_and_decode_sdjwt
from app.utils.encoding import b64url_decode_strict

logger = logging.getLogger(__name__)

REVOKED = 1
_HTTP_TIMEOUT = 15


def _headers() -> Dict[str, str]:
    """Returns the headers expected by the status list service.

    Returns:
        Form content type and API key headers.
    """
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Api-Key": CONFIGURATION["revocation"]["api_key"],
    }


def reserve_status_entry(doctype: str, country: str, expiry_date: str) -> Optional[Dict[str, Any]]:
    """Reserves a status list entry for a credential about to be issued.

    Args:
        doctype: Credential doctype (mdoc) or ``vct`` (SD-JWT).
        country: Issuing country.
        expiry_date: Credential expiry as ``YYYY-MM-DD``.

    Returns:
        The service response (``status_list`` / ``identifier_list``
        pointers), or ``None`` when the service does not answer ``200``.
    """
    response = requests.post(
        CONFIGURATION["revocation"]["take_url"],
        headers=_headers(),
        data=f"doctype={doctype}&country={country}&expiry_date={expiry_date}",
        timeout=_HTTP_TIMEOUT,
    )
    if response.status_code != 200:
        logger.warning(f"Status list reservation failed for {doctype}: HTTP {response.status_code}")
        return None
    return response.json()


def set_token_status(
    field: str,
    value: Any,
    uri: str,
    status: int = REVOKED,
    respect_enabled_flag: bool = True,
) -> bool:
    """Sets the status of one status list entry.

    Args:
        field: ``"idx"`` for a ``status_list`` pointer or ``"id"`` for an
            ``identifier_list`` pointer.
        value: Index / identifier.
        uri: Status list URI.
        status: New status (``1`` = revoked).
        respect_enabled_flag: Skip the call when ``revocation.enabled`` is
            false in the configuration.

    Returns:
        ``True`` if the service accepted the update; ``False`` when skipped
        or on any error (errors are logged, never raised).
    """
    if respect_enabled_flag and not CONFIGURATION["revocation"].get("enabled", True):
        logger.info(f"Revocation disabled via config; skipping set for {uri}")
        return False

    try:
        response = requests.post(
            CONFIGURATION["revocation"]["set_url"],
            data={field: value, "status": status, "uri": uri},
            headers=_headers(),
            timeout=_HTTP_TIMEOUT,
        )
        response.raise_for_status()
    except Exception:
        # Never abort a multi-entry revocation because one entry failed.
        logger.exception(f"Failed to set status {status} for {field}={value}, uri={uri}")
        return False

    logger.info(f"Set token status {status} for {field}={value}, uri={uri}")
    return True


def get_status_sdjwt(sd_jwt: str) -> Dict[str, Any]:
    """Verifies a presented SD-JWT and returns its ``status`` claim.

    Args:
        sd_jwt: SD-JWT in compact serialization.

    Returns:
        The ``status`` claim.

    Raises:
        ValueError: If the SD-JWT or its ``x5c`` certificate is invalid.
        KeyError: If the credential has no ``status`` claim.
    """
    return verify_and_decode_sdjwt(sd_jwt)["status"]


def _mso_status(document: Dict[str, Any]) -> Dict[str, Any]:
    """Reads the ``status`` from a document's Mobile Security Object.

    Args:
        document: Decoded mdoc ``documents[i]`` entry.

    Returns:
        The MSO ``status`` map.
    """
    return cbor2.loads(cbor2.loads(document["issuerSigned"]["issuerAuth"][2]).value)["status"]


def get_status_mdoc(mdoc_credential: str) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """Decodes a base64url mdoc response and extracts its status information.

    Args:
        mdoc_credential: Base64url encoded ``DeviceResponse``.

    Returns:
        The status map for a single document, or a list of them for several.

    Raises:
        ValueError: If the input is not valid base64url.
    """
    documents = cbor2.loads(b64url_decode_strict(mdoc_credential))["documents"]
    statuses = [_mso_status(document) for document in documents]
    return statuses[0] if len(statuses) == 1 else statuses


def describe_status_list(status: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Derives display information from a ``status_list`` URI.

    The URI path is expected to look like
    ``/<a>/<b>/<doctype>/<status_list_identifier>/...``.

    Args:
        status: A credential ``status`` claim.

    Returns:
        ``{"doctype", "status_list_identifier"}``, or ``None`` when the
        status has no ``status_list`` pointer or its URI path is too short.
    """
    if "status_list" not in status:
        return None
    uri = status["status_list"].get("uri", "")
    path_parts = urlparse(uri).path.strip("/").split("/")
    if len(path_parts) < 4:
        logger.warning(f"Cannot derive doctype / list identifier from status list URI: {uri}")
        return None
    return {"doctype": path_parts[2], "status_list_identifier": path_parts[3]}

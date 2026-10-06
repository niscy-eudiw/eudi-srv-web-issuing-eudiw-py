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
"""Client for the OAuth authorization server and the status-list validator."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import requests

from app.core.config import CONFIGURATION
from app.utils.http import DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

#: Status-list validator context for wallet / key storage status lists.
WALLET_STATUS_CONTEXT = "WalletOrKeyStorageStatus"


def authorization_server_url() -> str:
    """Returns the base URL used to reach the authorization server.

    The ``internal_url`` (e.g. inside a container network) takes precedence
    over the public ``base_url``.

    Returns:
        Base URL without trailing slash.
    """
    auth_server = CONFIGURATION["authorization_server"]
    return auth_server.get("internal_url") or auth_server["base_url"]


def introspect(bearer_token: str) -> requests.Response:
    """Calls the authorization server's token introspection endpoint.

    Args:
        bearer_token: Access token to introspect.

    Returns:
        The HTTP response.

    Raises:
        requests.RequestException: On network errors.
    """
    return requests.request(
        "POST",
        f"{authorization_server_url()}/introspection",
        headers=_FORM_HEADERS,
        data=f"token={bearer_token}",
        timeout=DEFAULT_TIMEOUT,
    )


def generate_preauth_code(scope: str) -> Dict[str, Any]:
    """Asks the authorization server for a pre-authorized code.

    Args:
        scope: Space separated credential configuration ids.

    Returns:
        JSON with ``preauth_code``, ``session_id`` and ``tx_code``.

    Raises:
        requests.RequestException: On network errors.
    """
    response = requests.request(
        "POST",
        f"{authorization_server_url()}/preauth_generate",
        headers=_FORM_HEADERS,
        data=f"scope={scope}",
        timeout=DEFAULT_TIMEOUT,
    )
    return response.json()


class StatusCheckError(Exception):
    """Raised when the status-list validator cannot give a verdict.

    Covers network errors, ``400`` (bad request / index out of range),
    ``403`` (status list token signer rejected by the trust validator),
    ``502`` (status list unreachable or its JWT invalid) and malformed answers.
    """


def status_validation_context() -> str:
    """Returns the ``validation_context`` sent to the status-list validator.

    WIA (``client_status``) and key attestation (``key_storage_status``)
    status lists are signed by the wallet provider, hence the default
    ``WalletOrKeyStorageStatus`` (overridable with
    ``status_validator.validation_context``).

    Returns:
        The validation context.
    """
    return (CONFIGURATION.get("status_validator") or {}).get("validation_context", WALLET_STATUS_CONTEXT)


def check_status_list_revocation(
    url: str,
    status_idx: int,
    status_uri: str,
    timeout: int = 10,
    validation_context: Optional[str] = None,
) -> bool:
    """Checks a WIA / KA status list entry with the status-list validator.

    Uses the validator's single-check mode (``POST /status`` with ``idx``,
    ``uri`` and ``validation_context``).

    Args:
        url: Validator ``/status`` endpoint.
        status_idx: Status list index.
        status_uri: Status list token URI.
        timeout: Request timeout in seconds.
        validation_context: Trust validator context for the status list
            signer; defaults to :func:`status_validation_context`.

    Returns:
        ``True`` if the entry is revoked (``valid`` is ``False``),
        ``False`` if it is valid.

    Raises:
        StatusCheckError: If the validator is unreachable, answers an error
            (its ``error`` message is included) or returns no ``valid`` flag.
    """
    try:
        response = requests.post(
            url,
            json={
                "idx": status_idx,
                "uri": status_uri,
                "validation_context": validation_context or status_validation_context(),
            },
            headers={"accept": "application/json", "Content-Type": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise StatusCheckError(f"Status validator unreachable: {e}") from e

    try:
        data = response.json()
    except ValueError:
        data = {}

    if response.status_code != 200:
        raise StatusCheckError(f"Status validator HTTP {response.status_code}: {data.get('error', response.text)}")

    logger.info(f"Revocation check response: {data}")
    valid = data.get("valid")
    if not isinstance(valid, bool):
        raise StatusCheckError(f"Status validator returned no 'valid' flag: {data}")
    return valid is False

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
"""Construction of OpenID4VCI credential offers.

Attributes:
    PRE_AUTHORIZED_GRANT: Grant type URN of the pre-authorized code flow.
    TX_CODE_DESCRIPTION: ``tx_code`` description shown by wallets.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, Iterable, Optional

PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
TX_CODE_DESCRIPTION = "Please provide the one-time code."

CredentialOffer = Dict[str, Any]

#: Offer URI prefixes a user may choose: ``scheme://`` plus an optional path,
#: with no characters that could leave an HTML attribute or a URL.
_OFFER_PREFIX = re.compile(r"[a-z][a-z0-9+.\-]{0,31}://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%\-]{0,200}")
#: Schemes that run code or read local data when a link is opened.
_FORBIDDEN_OFFER_SCHEMES = frozenset({"javascript", "data", "vbscript", "file", "blob", "about"})


def is_valid_offer_prefix(prefix: Optional[str]) -> bool:
    """Tells whether a user-chosen credential offer URI prefix is acceptable.

    Args:
        prefix: For example ``openid-credential-offer://`` or
            ``https://wallet.example/``.

    Returns:
        ``True`` for a ``scheme://...`` prefix whose scheme cannot run code.
    """
    if not prefix or not _OFFER_PREFIX.fullmatch(prefix):
        return False
    return prefix.split(":", 1)[0] not in _FORBIDDEN_OFFER_SCHEMES


def authorization_code_offer(
    credential_issuer: str, credential_configuration_ids: Iterable[str], issuer_state: str
) -> CredentialOffer:
    """Builds an authorization code flow credential offer.

    Args:
        credential_issuer: Credential issuer identifier (frontend URL).
        credential_configuration_ids: Offered configuration ids.
        issuer_state: Value bound to the later authorization request.

    Returns:
        The credential offer.
    """
    return {
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": list(credential_configuration_ids),
        "grants": {"authorization_code": {"issuer_state": issuer_state}},
    }


def pre_authorized_offer(
    credential_issuer: str,
    credential_configuration_ids: Iterable[str],
    issuer_state: str,
    pre_authorized_code: str,
    tx_code_value: Optional[Any] = None,
) -> CredentialOffer:
    """Builds a pre-authorized code flow credential offer.

    Args:
        credential_issuer: Credential issuer identifier (frontend URL).
        credential_configuration_ids: Offered configuration ids.
        issuer_state: Issuance session id.
        pre_authorized_code: Code issued by the authorization server.
        tx_code_value: When given, the transaction code is embedded in the
            offer (test / wallet-tester flows only).

    Returns:
        The credential offer.
    """
    tx_code: Dict[str, Any] = {"length": 5, "input_mode": "numeric", "description": TX_CODE_DESCRIPTION}
    if tx_code_value is not None:
        tx_code["value"] = tx_code_value
    return {
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": list(credential_configuration_ids),
        "grants": {
            PRE_AUTHORIZED_GRANT: {
                "issuer_state": issuer_state,
                "pre-authorized_code": pre_authorized_code,
                "tx_code": tx_code,
            }
        },
    }


def credential_offer_uri(scheme: str, credential_offer: CredentialOffer) -> str:
    """Builds a by-value credential offer URI.

    Args:
        scheme: URI prefix, e.g. ``openid-credential-offer://``.
        credential_offer: The offer.

    Returns:
        ``<scheme>credential_offer?credential_offer=<urlencoded JSON>``.
    """
    return f"{scheme}credential_offer?credential_offer=" + urllib.parse.quote(
        json.dumps(credential_offer), safe=":/"
    )

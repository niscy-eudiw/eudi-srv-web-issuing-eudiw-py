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
"""Per-frontend issuer metadata (unsigned and signed).

Each frontend (``frontend.frontends_config.<frontend_id>``) publishes its own
credential issuer metadata. This module builds it from the frontend
templates in ``metadata_config/`` and the backend's public metadata
(:data:`app.core.state.oidc_metadata_clean`), exactly as the frontend used to
do at start-up:

* ``credential_configurations_supported``, ``credential_request_encryption``
  and ``issuer_info`` come from the backend metadata, optionally filtered by
  the frontend's ``credentials_supported`` list;
* template URLs on ``<template domain>/oidc`` point to the authorization
  server (``oauth_url``), all other template URLs to the backend
  (``service_url``);
* ``credential_issuer``, the OpenID ``issuer``, the PAR endpoint and the
  display logo point to the frontend's own URL.

Per-frontend configuration keys:
    url (required): Public URL of the frontend (the credential issuer identifier).
    credentials_supported (optional): List of configuration ids, or ``"*"`` /
        absent for all.
    oauth_url (optional): Public authorization server URL; defaults to
        ``authorization_server.base_url``.
"""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

from app.core.config import CONFIGURATION
from app.core.state import oidc_metadata_clean
from app.services.metadata import METADATA_DIR, replace_domain, sign_issuer_metadata
from app.utils.frontend import frontend_config

TEMPLATE_DIR = METADATA_DIR
_COPIED_BACKEND_FIELDS = ("credential_request_encryption", "issuer_info")


class UnknownFrontendError(KeyError):
    """Raised when a frontend id is not configured."""


@dataclass(frozen=True)
class FrontendMetadata:
    """The metadata documents a frontend publishes.

    Attributes:
        openid_credential_issuer: ``/.well-known/openid-credential-issuer``.
        openid_configuration: ``/.well-known/openid-configuration``.
        oauth_authorization_server: ``/.well-known/oauth-authorization-server``.
    """

    openid_credential_issuer: Dict[str, Any]
    openid_configuration: Dict[str, Any]
    oauth_authorization_server: Dict[str, Any]

    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        """Returns the documents keyed by attribute name."""
        return asdict(self)


@lru_cache(maxsize=None)
def _load_template(name: str, template_dir: Path = TEMPLATE_DIR) -> Dict[str, Any]:
    """Loads (once) a frontend metadata template.

    Args:
        name: File name in ``template_dir``.
        template_dir: Template directory.

    Returns:
        The parsed template (never mutate; it is cached).
    """
    with open(template_dir / name, encoding="utf-8") as f:
        return json.load(f)


def _template(name: str) -> Dict[str, Any]:
    """Returns a private copy of a frontend template.

    Args:
        name: Template file name.

    Returns:
        A deep copy safe to modify.
    """
    return copy.deepcopy(_load_template(name))


def _frontend(frontend_id: str) -> Dict[str, Any]:
    """Returns the configuration of a frontend.

    Args:
        frontend_id: Frontend identifier.

    Returns:
        ``frontend.frontends_config[frontend_id]``.

    Raises:
        UnknownFrontendError: If the frontend is not configured.
    """
    if not frontend_id or frontend_id not in CONFIGURATION.get("frontend", {}).get("frontends_config", {}):
        raise UnknownFrontendError(frontend_id)
    return frontend_config(frontend_id)


def _supported_credentials(allowed: Optional[Any]) -> Dict[str, Any]:
    """Returns the backend credential configurations, filtered for a frontend.

    Args:
        allowed: The frontend's ``credentials_supported`` (list, ``"*"`` or ``None``).

    Returns:
        A copy of the (filtered) ``credential_configurations_supported``.
    """
    credentials = copy.deepcopy(oidc_metadata_clean.get("credential_configurations_supported", {}))
    if not allowed or allowed == "*" or allowed == ["*"]:
        return credentials
    allowed_ids = set(allowed)
    return {cid: cfg for cid, cfg in credentials.items() if cid in allowed_ids}


def build_frontend_metadata(frontend_id: str) -> FrontendMetadata:
    """Builds the unsigned metadata documents of a frontend.

    Args:
        frontend_id: Frontend identifier.

    Returns:
        The frontend's metadata documents.

    Raises:
        UnknownFrontendError: If the frontend is not configured.
    """
    frontend = _frontend(frontend_id)
    frontend_url = frontend["url"]
    backend_url = CONFIGURATION["service_url"]
    oauth_url = frontend.get("oauth_url") or CONFIGURATION["authorization_server"]["base_url"]

    issuer_metadata = _template("metadata_config.json")
    issuer_metadata["credential_configurations_supported"] = _supported_credentials(
        frontend.get("credentials_supported")
    )
    for field in _COPIED_BACKEND_FIELDS:
        if field in oidc_metadata_clean:
            issuer_metadata[field] = copy.deepcopy(oidc_metadata_clean[field])

    template_domain = issuer_metadata["credential_issuer"]

    openid_configuration = replace_domain(_template("openid-configuration.json"), f"{template_domain}/oidc", oauth_url)
    oauth_authorization_server = replace_domain(_template("oauth-authorization-server.json"), template_domain, backend_url)
    issuer_metadata = replace_domain(issuer_metadata, template_domain, backend_url)

    openid_configuration["issuer"] = frontend_url
    openid_configuration["pushed_authorization_request_endpoint"] = f"{frontend_url}/pushed_authorization"
    issuer_metadata["credential_issuer"] = frontend_url
    issuer_metadata["display"][0]["logo"]["uri"] = f"{frontend_url}/ic-logo.png"

    return FrontendMetadata(
        openid_credential_issuer=issuer_metadata,
        openid_configuration=openid_configuration,
        oauth_authorization_server=oauth_authorization_server,
    )


def sign_frontend_metadata(frontend_id: str) -> str:
    """Builds and signs the credential issuer metadata of a frontend.

    The JWT is signed with the frontend's metadata signing key; ``iss`` and
    ``sub`` are the frontend URL (OpenID4VCI 12.2.3).

    Args:
        frontend_id: Frontend identifier.

    Returns:
        The signed metadata JWT.

    Raises:
        UnknownFrontendError: If the frontend is not configured.
        MetadataSigningError: If the key / certificate cannot be loaded.
    """
    metadata = build_frontend_metadata(frontend_id).openid_credential_issuer
    return sign_issuer_metadata(metadata, frontend_id, iss=frontend_config(frontend_id)["url"])

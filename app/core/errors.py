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
"""Shared exceptions and error responses.

Centralizes the OpenID4VCI credential error body, the OAuth error redirect,
the formatter error body and the application-wide Flask error handlers.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, Optional, Tuple

from flask import Response, jsonify, redirect, request
from werkzeug.exceptions import HTTPException

from app.core.constants import ConfService as cfgservice
from app.utils.http import url_get

logger = logging.getLogger(__name__)

C_NONCE_EXPIRES_IN = 86400


class CertificateVerificationError(Exception):
    """Raised when certificate verification fails."""


class OAuthEndpointError(Exception):
    """An OAuth / OpenID4VCI error to return to the client as JSON.

    Raised by request parsing and validation helpers; blueprints render it
    with :func:`oauth_error_response`. Messages are fixed strings, never
    request input.

    Args:
        error: OAuth error code (e.g. ``invalid_credential_request``).
        status: HTTP status code.
        description: Optional fixed ``error_description``.
    """

    def __init__(self, error: str, status: int = 400, description: Optional[str] = None) -> None:
        super().__init__(error)
        self.error = error
        self.status = status
        self.description = description


def oauth_error_response(e: OAuthEndpointError) -> Tuple[Response, int]:
    """Renders an :class:`OAuthEndpointError` as a JSON response.

    Args:
        e: The error.

    Returns:
        ``(json_response, status)``.
    """
    body = {"error": e.error}
    if e.description:
        body["error_description"] = e.description
    return jsonify(body), e.status


def credential_error_resp(error: str, desc: str) -> Tuple[Response, int]:
    """Builds an OpenID4VCI credential endpoint error response.

    A fresh ``c_nonce`` is included so the wallet can retry.

    Args:
        error: OAuth error code (e.g. ``invalid_proof``).
        desc: Human readable description.

    Returns:
        ``(json_response, 400)``.
    """
    return (
        jsonify(
            {
                "error": error,
                "error_description": desc,
                "c_nonce": secrets.token_urlsafe(16),
                "c_nonce_expires_in": C_NONCE_EXPIRES_IN,
            }
        ),
        400,
    )


def auth_error_redirect(return_uri: str, error: str, error_description: Optional[str] = None) -> Response:
    """Redirects the wallet to ``return_uri`` with an OAuth error.

    Args:
        return_uri: Wallet redirect URI.
        error: OAuth error code.
        error_description: Optional description.

    Returns:
        A ``302`` redirect response.
    """
    error_msg = {"error": error}
    if error_description is not None:
        error_msg["error_description"] = error_description
    return redirect(url_get(return_uri, error_msg), code=302)


def formatter_result(error_code: int, field: str = "mdoc", value: str = "") -> Response:
    """Builds the JSON body returned by the ``/formatter`` endpoints.

    The endpoints always answer HTTP 200; failures are signalled through
    ``error_code`` (``0`` = success).

    Args:
        error_code: Key into :attr:`ConfService.error_list`.
        field: Name of the credential field in the body.
        value: The credential (empty on error).

    Returns:
        The JSON response.
    """
    return jsonify(
        {
            "error_code": error_code,
            "error_message": cfgservice.error_list[str(error_code)],
            field: value,
        }
    )


def handle_exception(e: Exception) -> Any:
    """Application-wide handler for uncaught exceptions.

    HTTP exceptions are returned unchanged; anything else is logged and
    turned into a generic JSON 500.

    Args:
        e: The raised exception.

    Returns:
        The HTTP exception, or ``(json_response, 500)``.
    """
    if isinstance(e, HTTPException):
        return e

    logger.exception("Unhandled exception")
    return (
        jsonify(
            {
                "error": "Internal Server Error",
                "error_code": 500,
                "message": "An internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
            }
        ),
        500,
    )


def page_not_found(e: Exception) -> Tuple[Response, int]:
    """JSON 404 handler.

    Args:
        e: The ``NotFound`` exception.

    Returns:
        ``(json_response, 404)``.
    """
    logger.warning("404 Not Found: %s", request.path)
    return (
        jsonify(
            {
                "error": "Not Found",
                "error_code": 404,
                "message": f"The requested path '{request.path}' could not be found.",
            }
        ),
        404,
    )

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
"""Authentication of internal service-to-service requests.

Endpoints used by other EUDIW services (log retrieval, client status) are
protected with a shared API key configured as ``backend_api_key`` in the
issuer YAML configuration. Callers send it in the ``X-Api-Key`` header.

Attributes:
    API_KEY_HEADER: Request header carrying the API key.
"""

from __future__ import annotations

import functools
import hmac
import logging
from typing import Any, Callable, Optional, TypeVar

from flask import jsonify, request

from app.core.config import CONFIGURATION

logger = logging.getLogger(__name__)

API_KEY_HEADER = "X-Api-Key"

F = TypeVar("F", bound=Callable[..., Any])


def configured_api_key() -> Optional[str]:
    """Returns the configured backend API key.

    Returns:
        ``CONFIGURATION["backend_api_key"]``, or ``None`` when unset / empty.
    """
    key = CONFIGURATION.get("backend_api_key")
    return str(key) if key else None


def is_valid_api_key(candidate: Optional[str]) -> bool:
    """Checks a presented API key in constant time.

    Args:
        candidate: Key sent by the caller.

    Returns:
        ``True`` if a key is configured and ``candidate`` matches it.
    """
    expected = configured_api_key()
    if not expected or not candidate:
        return False
    return hmac.compare_digest(candidate.encode(), expected.encode())


def require_api_key(view: F) -> F:
    """Decorator rejecting requests without the backend API key.

    Fails closed: when no ``backend_api_key`` is configured the endpoint
    answers ``503``.

    Args:
        view: Flask view function.

    Returns:
        The wrapped view. It answers ``401`` for a missing / wrong key and
        ``503`` when no key is configured.
    """

    @functools.wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if configured_api_key() is None:
            logger.error(f"{request.path} called but backend_api_key is not configured")
            return jsonify({"error": "service_unavailable", "error_description": "API key not configured"}), 503
        if not is_valid_api_key(request.headers.get(API_KEY_HEADER)):
            logger.warning(f"Rejected {request.path}: missing or invalid {API_KEY_HEADER}")
            return jsonify({"error": "unauthorized", "error_description": "Missing or invalid API key"}), 401
        return view(*args, **kwargs)

    return wrapper  # type: ignore[return-value]

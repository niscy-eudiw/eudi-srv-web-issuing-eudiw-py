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
"""Request authentication and CSRF protection.

* Endpoints used by other EUDIW services (log retrieval, client status,
  metadata) are protected with a shared API key configured as
  ``backend_api_key``; callers send it in the ``X-Api-Key`` header
  (:func:`require_api_key`).
* Browser form POSTs coming from the frontends are protected against
  cross-site request forgery by checking the ``Origin`` (or ``Referer``)
  header against the configured frontends (:func:`require_frontend_origin`).

Attributes:
    API_KEY_HEADER: Request header carrying the API key.
"""

from __future__ import annotations

import functools
import hmac
import logging
from typing import Any, Callable, Optional, TypeVar

from urllib.parse import urlsplit

from flask import jsonify, request

from app.core.config import CONFIGURATION
from app.core.log_utils import safe
from app.utils.frontend import allowed_cors_origins

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
            logger.error(f"{safe(request.path)} called but backend_api_key is not configured")
            return jsonify({"error": "service_unavailable", "error_description": "API key not configured"}), 503
        if not is_valid_api_key(request.headers.get(API_KEY_HEADER)):
            logger.warning(f"Rejected {safe(request.path)}: missing or invalid {API_KEY_HEADER}")
            return jsonify({"error": "unauthorized", "error_description": "Missing or invalid API key"}), 401
        return view(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _request_origin() -> Optional[str]:
    """Returns the browser origin of the current request.

    Returns:
        The ``Origin`` header, else the origin of ``Referer``, else ``None``.
    """
    origin = request.headers.get("Origin")
    if origin:
        return origin
    referer = request.headers.get("Referer")
    if referer:
        parts = urlsplit(referer)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
    return None


def trusted_browser_origins() -> set[str]:
    """Origins allowed to POST browser forms to the backend.

    Returns:
        The configured frontends, ``cors_allowed_origins`` and the backend's
        own ``service_url`` origin.
    """
    origins = set(allowed_cors_origins())
    service = urlsplit(CONFIGURATION.get("service_url", ""))
    if service.scheme and service.netloc:
        origins.add(f"{service.scheme}://{service.netloc}")
    return origins


def require_frontend_origin(view: F) -> F:
    """Decorator rejecting cross-site browser POSTs (CSRF protection).

    State-changing requests (anything but GET / HEAD / OPTIONS) must come
    from a trusted origin. Browsers always send ``Origin`` on cross-origin
    POSTs, so a forged request from another site is rejected; requests
    without ``Origin`` and ``Referer`` (non-browser clients) are allowed.

    Args:
        view: Flask view function.

    Returns:
        The wrapped view, answering ``403`` for untrusted origins.
    """

    @functools.wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = _request_origin()
            if origin is not None and origin not in trusted_browser_origins():
                logger.warning(f"Rejected cross-site {request.method} to {safe(request.path)} from origin {safe(origin, 100)}")
                return jsonify({"error": "forbidden", "error_description": "Untrusted request origin"}), 403
            if origin is None:
                logger.debug(f"{request.method} {safe(request.path)} without Origin/Referer (non-browser client)")
        return view(*args, **kwargs)

    return wrapper  # type: ignore[return-value]

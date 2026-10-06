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
"""HTTP helpers: URL building and browser POST-redirects.

Attributes:
    DEFAULT_TIMEOUT: Timeout (seconds) applied to outgoing HTTP calls.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Mapping

from flask import json, render_template_string

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30

_AUTO_SUBMIT_HTML = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Redirecting...</title>
        <style>
            body { margin: 0; padding: 0; overflow: hidden; }
            #redirect_form { display: none; }
        </style>
    </head>
    <body>
        <form id="redirect_form" method="POST" action="{{ url }}">
            <input type="hidden" name="payload" value='{{ data | safe }}'>
            <noscript>
                <div style="font-family: sans-serif; padding: 20px; text-align: center;">
                    <p>JavaScript is required. Please click the button below:</p>
                    <button type="submit" style="padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer;">
                        Continue
                    </button>
                </div>
            </noscript>
        </form>
        <script>
            // Submit immediately without waiting for full page load
            document.getElementById('redirect_form').submit();
        </script>
    </body>
    </html>
    """


def url_get(url_path: str, args: Mapping[str, Any]) -> str:
    """Builds the URL of an HTTP GET query.

    Args:
        url_path: URL without query string.
        args: Query parameters.

    Returns:
        ``url_path?<urlencoded args>``.
    """
    return url_path + "?" + urllib.parse.urlencode(args)


def post_redirect_with_payload(target_url: str, data_payload: Mapping[str, Any]) -> str:
    """Renders an auto-submitting HTML form that POSTs ``data_payload``.

    This simulates an HTTP POST redirect, passing a JSON payload to another
    service without hitting URL length limits.

    Args:
        target_url: URL the browser should be POSTed to.
        data_payload: Dictionary serialized as JSON into the ``payload`` field.

    Returns:
        The rendered intermediate HTML page.
    """
    return render_template_string(
        _AUTO_SUBMIT_HTML, url=target_url, data=json.dumps(data_payload)
    )

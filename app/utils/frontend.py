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
"""Lookup helpers for the frontend configuration section."""

from __future__ import annotations

from typing import Any, Optional

from app.core.config import CONFIGURATION


def frontend_config(frontend_id: Optional[str] = None) -> dict[str, Any]:
    """Returns the configuration block of a frontend.

    Args:
        frontend_id: Frontend identifier; the default frontend when falsy.

    Returns:
        The ``frontend.frontends_config[<id>]`` mapping.

    Raises:
        KeyError: If the frontend is not configured.
    """
    frontends = CONFIGURATION["frontend"]
    return frontends["frontends_config"][frontend_id or frontends["default"]]


def frontend_url(frontend_id: Optional[str] = None) -> str:
    """Returns the base URL of a frontend.

    Args:
        frontend_id: Frontend identifier; the default frontend when falsy.

    Returns:
        The frontend base URL.

    Raises:
        KeyError: If the frontend is not configured.
    """
    return frontend_config(frontend_id)["url"]

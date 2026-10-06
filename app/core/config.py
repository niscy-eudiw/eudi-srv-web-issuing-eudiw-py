# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
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
"""Runtime configuration loading for the PID Issuer.

The issuer is configured through a YAML file whose location is given by the
``ISSUER_CONFIG_PATH`` environment variable. Key and certificate paths found
in the file are resolved eagerly and their contents stored next to the path
(e.g. ``private_key_path`` -> ``private_key``) so that the rest of the code
base never touches the filesystem for key material.

When ``MOCK_CONFIGURATION`` is set (test / CI runs) a minimal in-memory
configuration is used instead.

Attributes:
    CONFIGURATION: The process-wide configuration dictionary.
    IS_TEST_ENV: ``True`` when running under pytest or in CI.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

DEFAULT_CONFIG_PATH = "/etc/issuer_config/config_issuer_backend.yaml"


def _load_file(path: str) -> bytes:
    """Reads a file as raw bytes.

    Args:
        path: Filesystem path to read.

    Returns:
        The file contents.

    Raises:
        OSError: If the file cannot be read.
    """
    with open(path, "rb") as f:
        return f.read()


def process_config(config: dict[str, Any]) -> dict[str, Any]:
    """Loads all key/certificate files referenced by the configuration.

    For every frontend, the global ``keys`` section and every country key
    entry, the ``*_path`` value is read and the bytes are stored under the
    matching key without the ``_path`` suffix.

    Args:
        config: Parsed YAML configuration. Mutated in place.

    Returns:
        The same ``config`` object, for convenience.

    Raises:
        OSError: If a referenced key or certificate file cannot be read.
        KeyError: If a mandatory section is missing.
    """
    for frontend in config["frontend"]["frontends_config"].values():
        frontend["metadata_signing_key"] = _load_file(frontend["metadata_signing_key_path"])
        frontend["metadata_access_certificate"] = _load_file(
            frontend["metadata_access_certificate_path"]
        )

    keys = config["keys"]
    keys["nonce_key"] = _load_file(keys["nonce_path"])
    keys["credential_encryption_key"] = _load_file(keys["credential_request_path"])

    for country in config["countries"].values():
        # Each entry name is either "_default" or a frontend UUID.
        for entry in country["keys"].values():
            entry["private_key"] = _load_file(entry["private_key_path"])
            entry["certificate"] = _load_file(entry["certificate_path"])

    return config


def load_config(path: str | None = None) -> dict[str, Any]:
    """Reads and processes the issuer YAML configuration.

    Args:
        path: Explicit configuration path. Defaults to ``ISSUER_CONFIG_PATH``
            or :data:`DEFAULT_CONFIG_PATH`.

    Returns:
        The processed configuration dictionary.

    Raises:
        RuntimeError: If the file is missing, empty or not valid YAML.
    """
    config_path = path or os.environ.get("ISSUER_CONFIG_PATH", DEFAULT_CONFIG_PATH)
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise RuntimeError(f"Config file not found: {config_path}") from e
    except yaml.YAMLError as e:
        raise RuntimeError(f"Invalid YAML in config: {e}") from e

    if not config:
        raise RuntimeError(f"Config file is empty: {config_path}")

    return process_config(config)


def mock_config() -> dict[str, Any]:
    """Returns the minimal configuration used when ``MOCK_CONFIGURATION`` is set.

    Returns:
        A configuration dictionary sufficient to import the application
        (no database: background services are disabled in tests).
    """
    return {"expiry": {"session": 30}}


def _detect_test_env() -> bool:
    """Detects whether the process runs under pytest or a CI pipeline.

    Returns:
        ``True`` for pytest, ``CI=true`` or ``SONARCLOUD=true``.
    """
    return (
        "pytest" in sys.modules
        or any("pytest" in arg for arg in sys.argv)
        or os.getenv("CI") == "true"
        or os.getenv("SONARCLOUD") == "true"
    )


CONFIGURATION: dict[str, Any] = mock_config() if os.getenv("MOCK_CONFIGURATION") else load_config()

IS_TEST_ENV: bool = _detect_test_env()


def feature_enabled(name: str) -> bool:
    """Tells whether a test-only feature is switched on.

    Test features (``test_features.<name>`` in the configuration) let a demo
    issuer accept self-asserted data. They are off unless set to ``true``.

    Args:
        name: Feature name, for example ``form_countries``.

    Returns:
        ``True`` only when the configuration sets the feature to ``true``.
    """
    features = CONFIGURATION.get("test_features") if isinstance(CONFIGURATION, dict) else None
    return isinstance(features, dict) and features.get(name) is True

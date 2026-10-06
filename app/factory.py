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
"""Flask application factory of the EUDIW PID Issuer.

The PID Issuer Web service is a component of the PID Provider backend. Its
main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT
format.

Start-up work with external side effects (Postgres pool, nightly sweep
scheduler, trusted CA loading) happens in :func:`create_app`, never at
import time, and is skipped in test environments unless explicitly enabled
with ``INIT_BACKGROUND_SERVICES`` / ``LOAD_TRUSTED_CAS``.
"""

from __future__ import annotations

import os
from typing import Any, Mapping, Optional

from flask import Flask
from flask_cors import CORS
from flask_session import Session

from app.core import config as app_config
from app.core.errors import handle_exception, page_not_found
from app.core.logging_setup import configure_logging
from app.utils.frontend import allowed_cors_origins

#: Blueprints registered by :func:`create_app`, as ``(module, attribute)``.
BLUEPRINTS = (
    ("app.routes.formatter", "formatter"),
    ("app.routes.oidc", "oidc"),
    ("app.routes.revocation", "revocation"),
    ("app.routes.oid4vp", "oid4vp"),
    ("app.routes.dynamic", "dynamic"),
    ("app.routes.preauth", "preauth"),
    ("app.routes.metadata", "metadata"),
)


def _register_blueprints(app: Flask) -> None:
    """Imports and registers every blueprint in :data:`BLUEPRINTS`.

    Args:
        app: The application.
    """
    import importlib

    for module_name, attribute in BLUEPRINTS:
        app.register_blueprint(getattr(importlib.import_module(module_name), attribute))


def _start_background_services(app: Flask) -> None:
    """Initializes the status persistence pool and starts the nightly sweep.

    Args:
        app: The application (for logging).
    """
    from app.repositories.status_store import init_db_status
    from app.services.scheduler import start_scheduler

    init_db_status(app_config.CONFIGURATION["postgres"])
    start_scheduler()
    app.logger.info("Background services started (status DB pool, nightly sweep).")


def create_app(test_config: Optional[Mapping[str, Any]] = None) -> Flask:
    """Creates and configures the Flask application.

    Args:
        test_config: Configuration overriding the instance ``config.py``.
            ``INIT_BACKGROUND_SERVICES`` and ``LOAD_TRUSTED_CAS`` default to
            ``not IS_TEST_ENV``.

    Returns:
        The configured application.
    """
    # Imported here so tests can patch them on this module's namespace.
    from app.services.metadata import setup_metadata, setup_trusted_cas

    # API-only service: no static files are served.
    app = Flask(__name__, instance_relative_config=True, static_folder=None)
    app.config.from_mapping(
        SECRET_KEY="dev",
        INIT_BACKGROUND_SERVICES=not app_config.IS_TEST_ENV,
        LOAD_TRUSTED_CAS=not app_config.IS_TEST_ENV,
    )
    if test_config is None:
        app.config.from_pyfile("config.py", silent=True)
    else:
        app.config.from_mapping(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    configure_logging(app, app_config.CONFIGURATION["logging"])

    app.logger.info("Running initialization setups...")
    setup_metadata()
    if app.config["LOAD_TRUSTED_CAS"]:
        setup_trusted_cas()
    if app.config["INIT_BACKGROUND_SERVICES"]:
        _start_background_services(app)

    app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    @app.route("/", methods=["GET"])
    def health_check() -> tuple[str, int]:
        """Liveness probe."""
        return "OK", 200

    _register_blueprints(app)

    app.config["SESSION_FILE_THRESHOLD"] = 50
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # Only the configured frontends (and cors_allowed_origins) may call the
    # backend cross-origin with credentials (cookies).
    CORS(app, origins=allowed_cors_origins(), supports_credentials=True)

    app.logger.info(" - DEBUG - FLASK started")
    return app

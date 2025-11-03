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
"""
The PID Issuer Web service is a component of the PID Provider backend.
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.

This __init__.py serves double duty: it will contain the application factory, and it tells Python that the flask directory should be treated as a package.
"""

import copy
import json
import os
import sys

import requests

sys.path.append(os.path.dirname(__file__))

from flask import Flask, jsonify, render_template, send_from_directory
from flask_session import Session
from flask_cors import CORS
from werkzeug.debug import *
from werkzeug.exceptions import HTTPException
from typing import Dict, Any, List, Union, cast

from app_config.config_service import ConfService as cfgserv

# Log

oidc_metadata: Dict[str, Any] = {}
openid_metadata: Dict[str, Any] = {}
oauth_metadata: Dict[str, Any] = {}


def replace_domain(
    obj: Union[Dict[str, Any], List[Any], str, Any], old: str, new: str
) -> Union[Dict[str, Any], List[Any], str, Any]:
    if isinstance(obj, dict):
        return {k: replace_domain(v, old, new) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [replace_domain(i, old, new) for i in obj]
    elif isinstance(obj, str):
        return obj.replace(old, new)
    else:
        return obj


def setup_metadata():
    global oidc_metadata
    global oidc_metadata_clean
    global openid_metadata
    global oauth_metadata

    credentials_supported: Dict[str, Any] = {}

    try:
        dir_path = os.path.dirname(os.path.realpath(__file__))

        with open(dir_path + "/metadata_config/openid-configuration.json") as f:
            openid_metadata = json.load(f)

        with open(dir_path + "/metadata_config/oauth-authorization-server.json") as f:
            oauth_metadata = json.load(f)

        with open(dir_path + "/metadata_config/metadata_config.json") as metadata:
            oidc_metadata = json.load(metadata)
            oidc_metadata_clean = copy.deepcopy(oidc_metadata)

        metadata_endpoint = f"{cfgserv.issuer_url}/.well-known/openid-credential-issuer"

        try:
            response = requests.get(metadata_endpoint)
            response.raise_for_status()

            data = response.json()

            credentials_supported = data.get("credential_configurations_supported", {})

        except Exception:
            for file in os.listdir(
                dir_path + "/metadata_config/credentials_supported/"
            ):
                if file.endswith("json"):
                    json_path = os.path.join(
                        dir_path + "/metadata_config/credentials_supported/", file
                    )
                    with open(json_path, encoding="utf-8") as json_file:
                        credential = json.load(json_file)
                        credentials_supported.update(credential)

    except FileNotFoundError as e:
        cfgserv.app_logger.exception(f"Metadata Error: file not found. \n{e}")
        raise
    except json.JSONDecodeError as e:
        cfgserv.app_logger.exception(
            f"Metadata Error: Metadata Unable to decode JSON. \n{e}"
        )
        raise
    except Exception as e:
        cfgserv.app_logger.exception(
            f"Metadata Error: An unexpected error occurred. \n{e}"
        )
        raise

    oidc_metadata["credential_configurations_supported"] = credentials_supported

    old_domain = oidc_metadata["credential_issuer"]

    new_domain = cfgserv.service_url

    """ openid_metadata = cast(
        Dict[str, Any], replace_domain(openid_metadata, old_domain, new_domain)
    )
    oauth_metadata = cast(
        Dict[str, Any], replace_domain(oauth_metadata, old_domain, new_domain)
    )

    oidc_metadata = cast(
        Dict[str, Any], replace_domain(oidc_metadata, old_domain, new_domain)
    ) """


setup_metadata()


def handle_exception(e):
    # pass through HTTP errors
    if isinstance(e, HTTPException):
        return e
    cfgserv.app_logger.exception("- WARN - Error 500")
    # now you're handling non-HTTP exceptions only
    return (
        render_template(
            "misc/500.html",
            error="Sorry, an internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
            error_code="Internal Server Error",
        ),
        500,
    )


def page_not_found(e):
    cfgserv.app_logger.exception("- WARN - Error 404")
    return (
        render_template(
            "misc/500.html",
            error_code="Page not found",
            error="Page not found.We're sorry, we couldn't find the page you requested.",
        ),
        404,
    )


from typing import Optional


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    @app.route("/", methods=["GET"])
    def initial_page():
        return render_template(
            "misc/initial_page.html",
            oidc=f"{cfgserv.service_url}/.well-known/openid-credential-issuer",
            service_url=cfgserv.service_url,
        )

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory("static/images", "favicon.ico")

    @app.route("/ic-logo.png")
    def logo():
        return send_from_directory("static/images", "ic-logo.png")

    app.config.from_mapping(SECRET_KEY="dev")

    if test_config is None:
        # load the instance config (in instance directory), if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # register blueprint for the /pid route
    from . import frontend, auth_redirect

    app.register_blueprint(frontend.frontend)
    app.register_blueprint(auth_redirect.authorization_endpoint)

    # config session
    app.config["SESSION_FILE_THRESHOLD"] = 50
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # CORS is a mechanism implemented by browsers to block requests from domains other than the server's one.
    CORS(app, supports_credentials=True)

    cfgserv.app_logger.info(" - DEBUG - FLASK started")

    print(app.url_map)

    return app


#
# Usage examples:
# flask --app app run --debug
# flask --app app run --debug --cert=app/certs/certHttps.pem --key=app/certs/key.pem --host=127.0.0.1 --port=4430
#

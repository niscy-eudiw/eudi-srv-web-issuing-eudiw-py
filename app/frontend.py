import base64
import io
import json
import urllib
from urllib.parse import quote, urlencode
from flask_cors import CORS
import requests
from flask import (
    Blueprint,
    Response,
    make_response,
    request,
    redirect,
    render_template,
    url_for,
    jsonify,
)
import segno

from app_config.config_service import ConfService as cfgservice
from app import oidc_metadata, openid_metadata

frontend = Blueprint("frontend", __name__, url_prefix="/")
CORS(frontend)


@frontend.route("/display_countries", methods=["POST"])
def display_countries():
    cfgservice.app_logger.info(f"Testing")

    raw_json_string = request.form.get("payload")

    cfgservice.app_logger.info(f"raw_json_string: {raw_json_string}")

    if raw_json_string:
        try:

            data_payload = json.loads(raw_json_string)
            cfgservice.app_logger.info(f"data_payload: {data_payload}")

        except json.JSONDecodeError:
            return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

        session_id = data_payload.get("session_id")
        cfgservice.app_logger.info(f"session_id: {session_id}")
        countries = data_payload.get("countries")
        cfgservice.app_logger.info(f"countries: {countries}")

        return render_template(
            "dynamic/dynamic-countries.html",
            countries=countries,
            session_id=session_id,
            redirect_url=cfgservice.issuer_url,
        )

    return jsonify({"status": "error", "message": "Payload not found"}), 400


@frontend.route("/display_form", methods=["POST"])
def display_form():
    raw_json_string = request.form.get("payload")

    if raw_json_string:
        try:
            data_payload = json.loads(raw_json_string)

        except json.JSONDecodeError:
            return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

        session_id = data_payload.get("session_id")
        cfgservice.app_logger.info(f"session_id: {session_id}")
        mandatory_attributes = data_payload.get("mandatory_attributes")
        cfgservice.app_logger.info(f"mandatory_attributes: {mandatory_attributes}")
        optional_attributes = data_payload.get("optional_attributes")
        cfgservice.app_logger.info(f"optional_attributes: {optional_attributes}")
        redirect_url = data_payload.get("redirect_url")
        cfgservice.app_logger.info(f"redirect_url: {redirect_url}")

        return render_template(
            "dynamic/dynamic-form.html",
            mandatory_attributes=mandatory_attributes,
            optional_attributes=optional_attributes,
            redirect_url=redirect_url,
        )

    return jsonify({"status": "error", "message": "Payload not found"}), 400


@frontend.route("/display_authorization", methods=["POST"])
def display_authorization():
    raw_json_string = request.form.get("payload")

    if raw_json_string:
        try:
            data_payload = json.loads(raw_json_string)

        except json.JSONDecodeError:
            return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

        session_id = data_payload.get("session_id")
        cfgservice.app_logger.info(f"session_id: {session_id}")
        presentation_data = data_payload.get("presentation_data")
        cfgservice.app_logger.info(f"presentation_data: {presentation_data}")
        redirect_url = data_payload.get("redirect_url")
        cfgservice.app_logger.info(f"redirect_url: {redirect_url}")

        return render_template(
            "dynamic/form_authorize.html",
            presentation_data=presentation_data,
            user_id=session_id,
            redirect_url=redirect_url,
        )

    return jsonify({"status": "error", "message": "Payload not found"}), 400


@frontend.route("/credential_offer_choice", methods=["GET"])
def credential_offer():
    """Page for selecting credentials

    Loads credentials supported by EUDIW Issuer
    """
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    credentials = {"sd-jwt vc format": {}, "mdoc format": {}}

    for cred in credentialsSupported:
        credential = credentialsSupported[cred]

        if credential["format"] == "dc+sd-jwt":
            credentials["sd-jwt vc format"].update(
                {cred: credential["credential_metadata"]["display"][0]["name"]}
            )

        if credential["format"] == "mso_mdoc":
            credentials["mdoc format"].update(
                {cred: credential["credential_metadata"]["display"][0]["name"]}
            )

    return render_template(
        "openid/credential_offer.html",
        cred=credentials,
        redirect_url=cfgservice.service_url,
        credential_offer_URI="openid-credential-offer://",
    )


@frontend.route("/credential_offer", methods=["GET", "POST"])
def credentialOffer():

    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    cfgservice.app_logger.info(f"credentialsSupported: {credentialsSupported}")
    auth_choice = request.form.get("Authorization Code Grant")
    cfgservice.app_logger.info(f"auth_choice: {auth_choice}")

    form_keys = request.form.keys()
    credential_offer_URI = request.form.get("credential_offer_URI")

    cfgservice.app_logger.info(f"credential_offer_URI: {credential_offer_URI}")

    if "proceed" in form_keys:
        form = list(form_keys)
        form.remove("proceed")
        form.remove("credential_offer_URI")
        form.remove("Authorization Code Grant")
        all_exist = all(credential in credentialsSupported for credential in form)

        if all_exist:
            credentials_id = form
            credentials_id_list = json.dumps(form)
            if auth_choice == "pre_auth_code":
                """return redirect(
                    url_for("preauth.preauthRed", credentials_id=credentials_id_list)
                )"""
                params = {
                    "frontend_id": cfgservice.frontend_id,
                    "credentials_id": credentials_id_list,
                }
                target_url = f"{cfgservice.issuer_url}/preauth?{urlencode(params)}"
                return redirect(target_url)

            else:

                credential_offer = {
                    "credential_issuer": cfgservice.service_url[:-1],
                    "credential_configuration_ids": credentials_id,
                    "grants": {"authorization_code": {}},
                }

                # create URI
                json_string = json.dumps(credential_offer)

                uri = (
                    f"{credential_offer_URI}credential_offer?credential_offer="
                    + quote(json_string, safe=":/")
                )

                qrcode = segno.make(uri)
                out = io.BytesIO()
                qrcode.save(out, kind="png", scale=3)

                qr_img_base64 = "data:image/png;base64," + base64.b64encode(
                    out.getvalue()
                ).decode("utf-8")

                wallet_url = cfgservice.wallet_test_url + "credential_offer"

                return render_template(
                    "openid/credential_offer_qr_code.html",
                    wallet_dev=wallet_url
                    + "?credential_offer="
                    + json.dumps(credential_offer),
                    url_data=uri,
                    qrcode=qr_img_base64,
                )
        else:
            return redirect(cfgservice.service_url + "credential_offer_choice")

    else:
        return redirect(cfgservice.service_url + "credential_offer_choice")


@frontend.route("/.well-known/<service>")
def well_known(service):
    if service == "openid-credential-issuer":
        info = {
            "response": oidc_metadata,
            "http_headers": [
                ("Content-type", "application/json"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    elif service == "oauth-authorization-server":
        info = {
            "response": openid_metadata,
            "http_headers": [
                ("Content-type", "application/json"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    elif service == "openid-configuration":
        # _endpoint = current_app.server.get_endpoint("provider_config")
        info = {
            "response": openid_metadata,
            "http_headers": [
                ("Content-type", "application/json"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    else:
        return make_response("Not supported", 400)

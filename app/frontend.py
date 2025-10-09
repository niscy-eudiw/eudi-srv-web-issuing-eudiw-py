import base64
import io
import json
import urllib
from urllib.parse import quote, urlencode
from flask_cors import CORS
import requests
from flask import Blueprint, Response, request, redirect, render_template, url_for
import segno

from app_config.config_service import ConfService as cfgservice
from app import oidc_metadata

frontend = Blueprint("frontend", __name__, url_prefix="/")
CORS(frontend)


@frontend.route("/display_countries", methods=["GET"])
def display_countries():
    session_id = request.args.get("session_id")
    cfgservice.app_logger.info(f"session_id: {session_id}")
    countries_json = request.args.get("countries")

    cfgservice.app_logger.info(f"countries_json: {countries_json}")

    countries = json.loads(countries_json)

    cfgservice.app_logger.info(f"countries: {countries}")
    
    return render_template(
        "dynamic/dynamic-countries.html",
        countries=countries,
        session_id=session_id,
        redirect_url= cfgservice.issuer_url
    )


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


@frontend.route("/credential_offer_choice", methods=["GET"])
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
                """ return redirect(
                    url_for("preauth.preauthRed", credentials_id=credentials_id_list)
                ) """
                params = {"frontend_id": "12345", "credentials_id": credentials_id_list}
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
    


import json
from urllib.parse import urlencode
from flask_cors import CORS
import requests
from flask import Blueprint, Response, request, redirect, render_template

from app_config.config_service import ConfService as cfgservice


frontend = Blueprint("frontend", __name__, url_prefix="/")
CORS(frontend)


@frontend.route("/display_countries", methods=["GET"])
def display_countries():
    session_id = request.args.get("session_id")
    countries_json = request.args.get("countries")
    authorization_details_json = request.args.get("authorization_details")

    countries = json.loads(countries_json)
    authorization_details = json.loads(authorization_details_json)

    return render_template(
        "dynamic/dynamic-countries.html",
        countries=countries,
        authorization_details=authorization_details,
        session_id=session_id
        redirect_url= cfgservice.issuer_url
    )

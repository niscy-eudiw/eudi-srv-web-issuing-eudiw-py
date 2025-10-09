from urllib.parse import urlencode
from flask_cors import CORS
import requests
from flask import (
    Blueprint,
    Response,
    request,
    redirect,
)

from app_config.config_service import ConfService as cfgservice

authorization_endpoint = Blueprint("authorization_endpoint", __name__, url_prefix="/")
CORS(authorization_endpoint)


@authorization_endpoint.route("/authorization", methods=["GET", "POST"])
def authorization():

    headers = {
        key: value for key, value in request.headers.items() if key.lower() != "host"
    }

    extra_param = {"frontend_id": "my_frontend_123"}

    if request.method == "GET":
        query_params = request.args.to_dict()
        query_params.update(extra_param)
        new_url = f"{cfgservice.issuer_url}?{urlencode(query_params)}"
        return redirect(new_url, code=307)

    else:
        # For non-GET, build form-encoded body with extra_param
        content_type = request.headers.get("Content-Type", "")

        if "application/x-www-form-urlencoded" in content_type:
            form_data = request.form.to_dict()
            form_data["frontend_id"] = "my_frontend_123"
            resp = requests.post(cfgservice.issuer_url, headers=headers, data=form_data)
        else:
            # For other POST content types, just forward raw
            resp = requests.post(
                cfgservice.issuer_url, headers=headers, data=request.get_data()
            )

    excluded_headers = ["content-encoding", "transfer-encoding", "connection"]
    response_headers = [
        (name, value)
        for (name, value) in resp.headers.items()
        if name.lower() not in excluded_headers
    ]

    return Response(
        resp.content, status=resp.status_code, headers=dict(response_headers)
    )

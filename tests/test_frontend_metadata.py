"""Tests for per-frontend issuer metadata (unsigned + signed) and its endpoints."""

import copy
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask

from app.routes.metadata import metadata as metadata_blueprint
from app.services import frontend_metadata
from app.services.frontend_metadata import (
    TEMPLATE_DIR,
    UnknownFrontendError,
    build_frontend_metadata,
    sign_frontend_metadata,
)
from app.services.metadata import replace_domain
from config_helpers import patch_configuration
from pki_helpers import make_cert

API_KEY = "test-api-key"
HEADERS = {"X-Api-Key": API_KEY}
FRONTEND_ID = "fe-1"
FRONTEND_URL = "https://frontend.test"
BACKEND_URL = "https://backend.test"
AUTH_URL = "https://auth.test/oidc"

BACKEND_CLEAN_METADATA = {
    "credential_issuer": BACKEND_URL,
    "credential_configurations_supported": {
        "eu.europa.ec.eudi.pid_mdoc": {"format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.pid.1"},
        "eu.europa.ec.eudi.pid_vc_sd_jwt": {"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
        "eu.europa.ec.eudi.mdl_mdoc": {"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"},
    },
    "credential_request_encryption": {"jwks": {"keys": [{"kid": "backend-kid"}]}, "encryption_required": False},
    "issuer_info": [{"format": "registration_cert", "data": "abc"}],
}


@pytest.fixture(scope="module")
def signing_material():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert("Frontend Metadata", "Frontend Metadata", key.public_key(), key, ca=False)
    return {
        "key": key,
        "cert": cert,
        "key_pem": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM),
    }


def _config(signing_material, **frontend_overrides):
    frontend = {
        "url": FRONTEND_URL,
        "metadata_signing_key": signing_material["key_pem"],
        "metadata_access_certificate": signing_material["cert_pem"],
        "metadata_signing_key_password": None,
        **frontend_overrides,
    }
    return {
        "service_url": BACKEND_URL,
        "backend_api_key": API_KEY,
        "admin_api_key": API_KEY,
        "authorization_server": {"base_url": AUTH_URL},
        "frontend": {"default": FRONTEND_ID, "frontends_config": {FRONTEND_ID: frontend}},
    }


@pytest.fixture
def config(signing_material):
    with patch_configuration(_config(signing_material)) as cfg:
        yield cfg


@pytest.fixture(autouse=True)
def backend_metadata():
    from unittest.mock import patch

    with patch.dict("app.core.state.oidc_metadata_clean", copy.deepcopy(BACKEND_CLEAN_METADATA), clear=True):
        yield


@pytest.fixture
def client():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(metadata_blueprint)
    return app.test_client()


def _frontend_reference(service_url, backend_url, oauth_url, credentials_supported_cfg, backend_data):
    """Reference copy of the frontend's former ``setup_metadata`` (domain logic)."""

    def load(name):
        with open(TEMPLATE_DIR / name) as f:
            return json.load(f)

    openid_metadata = load("openid-configuration.json")
    oauth_metadata = load("oauth-authorization-server.json")
    oidc_metadata = load("metadata_config.json")

    credentials_supported = backend_data.get("credential_configurations_supported", {})
    if credentials_supported_cfg and credentials_supported_cfg != ["*"] and credentials_supported_cfg != "*":
        allowed = set(credentials_supported_cfg)
        credentials_supported = {k: v for k, v in credentials_supported.items() if k in allowed}

    oidc_metadata["credential_configurations_supported"] = credentials_supported
    if backend_data.get("credential_request_encryption"):
        oidc_metadata["credential_request_encryption"] = backend_data["credential_request_encryption"]
    if backend_data.get("issuer_info"):
        oidc_metadata["issuer_info"] = backend_data["issuer_info"]

    old_domain = oidc_metadata["credential_issuer"]
    openid_metadata = replace_domain(openid_metadata, f"{old_domain}/oidc", oauth_url)
    oauth_metadata = replace_domain(oauth_metadata, old_domain, backend_url)
    oidc_metadata = replace_domain(oidc_metadata, old_domain, backend_url)

    openid_metadata["issuer"] = service_url
    openid_metadata["pushed_authorization_request_endpoint"] = f"{service_url}/pushed_authorization"
    oidc_metadata["credential_issuer"] = service_url
    oidc_metadata["display"][0]["logo"]["uri"] = f"{service_url}/ic-logo.png"
    return oidc_metadata, openid_metadata, oauth_metadata


class TestBuildFrontendMetadata:
    @pytest.mark.parametrize("credentials_supported", [None, "*", ["*"], ["eu.europa.ec.eudi.pid_mdoc"]])
    def test_matches_former_frontend_logic(self, signing_material, credentials_supported):
        overrides = {} if credentials_supported is None else {"credentials_supported": credentials_supported}
        with patch_configuration(_config(signing_material, **overrides)):
            documents = build_frontend_metadata(FRONTEND_ID)

        oidc, openid, oauth = _frontend_reference(
            FRONTEND_URL, BACKEND_URL, AUTH_URL, credentials_supported, copy.deepcopy(BACKEND_CLEAN_METADATA)
        )
        assert documents.openid_credential_issuer == oidc
        assert documents.openid_configuration == openid
        assert documents.oauth_authorization_server == oauth

    def test_key_fields(self, config):
        documents = build_frontend_metadata(FRONTEND_ID)
        issuer = documents.openid_credential_issuer

        assert issuer["credential_issuer"] == FRONTEND_URL
        assert issuer["credential_endpoint"] == f"{BACKEND_URL}/credential"
        assert issuer["display"][0]["logo"]["uri"] == f"{FRONTEND_URL}/ic-logo.png"
        assert issuer["credential_request_encryption"]["jwks"]["keys"][0]["kid"] == "backend-kid"
        assert issuer["issuer_info"] == BACKEND_CLEAN_METADATA["issuer_info"]
        assert set(issuer["credential_configurations_supported"]) == set(
            BACKEND_CLEAN_METADATA["credential_configurations_supported"]
        )
        assert documents.openid_configuration["issuer"] == FRONTEND_URL
        assert documents.openid_configuration["token_endpoint"] == f"{AUTH_URL}/token"
        assert documents.openid_configuration["pushed_authorization_request_endpoint"] == (
            f"{FRONTEND_URL}/pushed_authorization"
        )
        assert documents.oauth_authorization_server["token_endpoint"] == f"{BACKEND_URL}/oidc/token"

    def test_credentials_filter(self, signing_material):
        with patch_configuration(_config(signing_material, credentials_supported=["eu.europa.ec.eudi.mdl_mdoc"])):
            issuer = build_frontend_metadata(FRONTEND_ID).openid_credential_issuer
        assert list(issuer["credential_configurations_supported"]) == ["eu.europa.ec.eudi.mdl_mdoc"]

    def test_oauth_url_override(self, signing_material):
        with patch_configuration(_config(signing_material, oauth_url="https://public-as.test")):
            openid = build_frontend_metadata(FRONTEND_ID).openid_configuration
        assert openid["authorization_endpoint"] == "https://public-as.test/authorization"

    def test_templates_and_backend_state_not_mutated(self, config):
        first = build_frontend_metadata(FRONTEND_ID)
        first.openid_credential_issuer["credential_configurations_supported"].clear()
        first.openid_credential_issuer["display"][0]["name"] = "changed"

        second = build_frontend_metadata(FRONTEND_ID)
        assert second.openid_credential_issuer["credential_configurations_supported"]
        assert second.openid_credential_issuer["display"][0]["name"] != "changed"

    def test_unknown_frontend(self, config):
        with pytest.raises(UnknownFrontendError):
            build_frontend_metadata("nope")

    def test_signed_metadata(self, config, signing_material):
        token = sign_frontend_metadata(FRONTEND_ID)

        header = jwt.get_unverified_header(token)
        assert header["typ"] == "openidvci-issuer-metadata+jwt"
        assert header["alg"] == "ES256"
        payload = jwt.decode(token, signing_material["cert"].public_key(), algorithms=["ES256"])
        assert payload["iss"] == FRONTEND_URL
        assert payload["sub"] == FRONTEND_URL
        assert payload["credential_issuer"] == FRONTEND_URL
        assert payload["credential_configurations_supported"]


class TestEndpoints:
    PATHS = [
        ("get", f"/metadata/{FRONTEND_ID}"),
        ("get", f"/metadata/{FRONTEND_ID}/signed"),
        ("post", "/metadata/metadata_signer"),
    ]

    @pytest.mark.parametrize("method, path", PATHS)
    def test_api_key_required(self, client, config, method, path):
        response = getattr(client, method)(path, json={})
        assert response.status_code == 401

    @pytest.mark.parametrize("method, path", PATHS)
    def test_wrong_api_key(self, client, config, method, path):
        response = getattr(client, method)(path, json={}, headers={"X-Api-Key": "wrong"})
        assert response.status_code == 401

    def test_unsigned_documents(self, client, config):
        response = client.get(f"/metadata/{FRONTEND_ID}", headers=HEADERS)

        assert response.status_code == 200
        body = response.get_json()
        assert set(body) == {"openid_credential_issuer", "openid_configuration", "oauth_authorization_server"}
        assert body["openid_credential_issuer"]["credential_issuer"] == FRONTEND_URL

    def test_signed_document(self, client, config, signing_material):
        response = client.get(f"/metadata/{FRONTEND_ID}/signed", headers=HEADERS)

        assert response.status_code == 200
        payload = jwt.decode(
            response.get_json()["signed_metadata"], signing_material["cert"].public_key(), algorithms=["ES256"]
        )
        assert payload["credential_issuer"] == FRONTEND_URL

    @pytest.mark.parametrize("path", ["/metadata/unknown", "/metadata/unknown/signed"])
    def test_unknown_frontend(self, client, config, path):
        response = client.get(path, headers=HEADERS)

        assert response.status_code == 404
        assert response.get_json()["error"] == "unknown_frontend"

    def test_signing_error(self, client, signing_material):
        with patch_configuration(_config(signing_material, metadata_signing_key=b"not a key")):
            response = client.get(f"/metadata/{FRONTEND_ID}/signed", headers=HEADERS)
        assert response.status_code == 500
        assert response.get_json()["error"] == "Failed to load private key"

    def test_metadata_signer_with_key(self, client, config, signing_material):
        response = client.post(
            "/metadata/metadata_signer",
            json={"metadata": {"credential_issuer": FRONTEND_URL}, "issuer_frontend_id": FRONTEND_ID, "iss": "x"},
            headers=HEADERS,
        )

        assert response.status_code == 200
        payload = jwt.decode(
            response.get_json()["signed_metadata"], signing_material["cert"].public_key(), algorithms=["ES256"]
        )
        assert payload["iss"] == "x"
        assert payload["sub"] == FRONTEND_URL

    def test_metadata_signer_validation(self, client, config):
        response = client.post("/metadata/metadata_signer", json={"metadata": {}}, headers=HEADERS)
        assert response.status_code == 400


def test_module_exports_template_dir():
    assert (frontend_metadata.TEMPLATE_DIR / "metadata_config.json").exists()

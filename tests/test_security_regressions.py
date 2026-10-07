"""Regression tests for the findings of the 2026-07 security assessments.

Each test replays the attack request from the report against the routes and
asserts it is now rejected (or that the protected behaviour holds).
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from app.routes import dynamic as dynamic_routes
from app.routes import preauth as preauth_routes
from app.routes.dynamic import dynamic
from app.routes.preauth import preauth
from config_helpers import patch_configuration

CONFIG = {
    "service_url": "https://backend.test",
    "wallet_tester_url": "https://tester.test",
    "credential_offer_scheme": "openid-credential-offer://",
    "authorization_server": {"user_verify_endpoint": "https://as.test/verify"},
    "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
    "countries": {
        "FC": {"name": "FormEU", "supported_credential_ids": ["pid"]},
        "AV": {"name": "Age", "supported_credential_ids": ["pid"]},
        "OO": {"name": "Oh", "connection_type": "openid", "auth": {}, "supported_credential_ids": ["pid"]},
    },
}


def _session(**overrides):
    values = {
        "session_id": "s1",
        "country": "FC",
        "frontend_id": "fe",
        "jws_token": "jws",
        "credentials_requested": ["pid"],
        "authorization_details": [{"credential_configuration_id": "pid"}],
        "verified_attributes": None,
        "user_data": {"family_name": "Doe"},
        "tx_code": 12345,
        "pre_authorized_code": "code",
    }
    values.update(overrides)
    return MagicMock(**values)


@pytest.fixture
def config():
    return json.loads(json.dumps(CONFIG))


@pytest.fixture
def client(config):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(dynamic)
    app.register_blueprint(preauth)
    with patch_configuration(config):
        test_client = app.test_client()
        with test_client.session_transaction() as s:
            s["session_id"] = "s1"
        yield test_client


def _jwt(payload):
    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'ES256'})}.{b64(payload)}.sig"


class TestFormatterSigningOracle:
    """AUTH-VULN-10 / AUTHZ-VULN-07: /formatter/* signed caller-supplied claims."""

    def test_formatter_routes_are_gone(self, monkeypatch):
        from app.factory import create_app

        monkeypatch.setattr("app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc"))
        config = {
            "service_url": "https://backend.test/",
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
        }
        with patch_configuration(config):
            app = create_app(test_config={"TESTING": True, "SECRET_KEY": "k"})
            client = app.test_client()
            for path in ("/formatter/sd-jwt", "/formatter/cbor"):
                assert client.post(path, json={"country": "FC", "data": {}}).status_code == 404
        assert "formatter" not in app.blueprints


class TestSelfAssertedIdentity:
    """AUTHZ-VULN-13: identity data typed into the form became a signed PID."""

    def test_form_countries_not_offered_by_default(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes, "post_redirect_with_payload", return_value="page"
        ) as page, patch.object(dynamic_routes, "openid_authorization_url", return_value="https://idp.test/a"):
            response = client.get("/dynamic/")
        # Only the connector country is left, so it is selected directly.
        assert response.status_code == 302 and response.headers["Location"] == "https://idp.test/a"
        page.assert_not_called()

    @pytest.mark.parametrize("country", ["FC", "AV", "AV2", "sample", "XX"])
    def test_form_country_selection_rejected(self, client, country):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_country"
        ) as update_country:
            response = client.post("/dynamic/country_selected", data={"country": country})
        assert response.status_code == 400
        update_country.assert_not_called()

    def test_attribute_form_rejected_without_verified_pid(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as store:
            response = client.post("/dynamic/form", data={"proceed": "1", "family_name": "ATTACKER"})
        assert response.status_code == 403
        store.assert_not_called()

    def test_attribute_form_rejected_for_connector_country(self, client, config):
        config["test_features"] = {"form_countries": True}
        with patch.object(
            dynamic_routes.session_manager, "get_session", return_value=_session(country="OO")
        ), patch.object(dynamic_routes.session_manager, "update_user_data") as store:
            response = client.post("/dynamic/form", data={"proceed": "1", "family_name": "ATTACKER"})
        assert response.status_code == 403
        store.assert_not_called()

    def test_verified_pid_values_cannot_be_changed(self, client):
        verified = {"family_name": "Real", "birth_date": "1980-02-03", "nationality": ["PT"]}
        with patch.object(
            dynamic_routes.session_manager, "get_session", return_value=_session(verified_attributes=verified)
        ), patch.object(dynamic_routes.session_manager, "update_user_data") as store, patch.object(
            dynamic_routes, "presentation_formatter", return_value={}
        ), patch.object(dynamic_routes, "post_redirect_with_payload", return_value="consent"):
            response = client.post(
                "/dynamic/form",
                data={"proceed": "1", "family_name": "ATTACKER", "birth_date": "1990-01-01", "given_name": "Extra"},
            )
        assert response.status_code == 200
        stored = store.call_args.kwargs["user_data"]
        assert stored["family_name"] == "Real" and stored["birthdate"] == "1980-02-03"
        assert stored["given_name"] == "Extra"

    def test_passport_age_verification_needs_feature(self, client):
        session = _session(credentials_requested=["eu.europa.ec.eudi.age_verification_mdoc_passport"])
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=session), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as store, patch.object(dynamic_routes, "post_redirect_with_payload", return_value="page"):
            client.get("/dynamic/")
        store.assert_not_called()

    @pytest.mark.parametrize(
        "method, path",
        [
            ("get", '/preauth?credentials_id=["pid"]'),
            ("post", "/preauth_form"),
            ("post", "/form_authorize_generate"),
        ],
    )
    def test_preauth_form_flow_disabled_by_default(self, client, method, path):
        with patch.object(preauth_routes, "request_preauth_token") as token:
            response = getattr(client, method)(path, data={"proceed": "1", "family_name": "ATTACKER"})
        assert response.status_code == 403
        token.assert_not_called()

    def test_form_authorize_generate_ignores_client_user_id(self, client, config):
        """The offer is built for the browser's session, never a posted user_id."""
        config["test_features"] = {"form_countries": True}
        sessions = {"s1": _session(), "victim": _session(session_id="victim")}
        with patch.object(
            preauth_routes.session_manager, "get_session", side_effect=lambda session_id: sessions.get(session_id)
        ) as get_session, patch.object(preauth_routes, "generate_offer", return_value="offer") as offer:
            client.post("/form_authorize_generate", data={"user_id": "victim"})
        assert "victim" not in [c.args[0] if c.args else c.kwargs.get("session_id") for c in get_session.call_args_list]
        offer.assert_called_once_with(sessions["s1"].user_data)


class TestTxCodeInOffer:
    """The tx_code (second factor) travelled inside the credential offer."""

    def test_tx_code_returned_beside_the_offer(self, client):
        import time

        now = int(time.time())
        token = _jwt({"credentials": [{"credential_configuration_id": "pid", "data": {"family_name": "Doe"}}], "iat": now, "exp": now + 300})
        with patch.object(preauth_routes, "verify_jwt_with_x5c", side_effect=lambda t, **_: json.loads(
            base64.urlsafe_b64decode(t.split(".")[1] + "==")
        )), patch.object(preauth_routes, "request_preauth_token", return_value="s1"), patch.object(
            preauth_routes, "session_manager"
        ) as sessions:
            sessions.get_session.return_value = _session()
            response = client.post("/credentialOfferReq2", data={"request": token})
        body = response.get_json()
        assert body["tx_code"] == 12345
        grant = body["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        assert "value" not in grant["tx_code"]
        assert "12345" not in json.dumps(body["credential_offer"])


class TestReflectedOfferUri:
    """INJ-VULN-02 / XSS-VULN-05: credential_offer_URI was reflected into the page."""

    @pytest.mark.parametrize(
        "prefix",
        ["openid-credential-offer://", "haip-vci://", "eudi-openid4ci://", "https://wallet.example/offer/"],
    )
    def test_wallet_prefixes_accepted(self, prefix):
        from app.services.credential_offer import is_valid_offer_prefix

        assert is_valid_offer_prefix(prefix)

    @pytest.mark.parametrize(
        "prefix",
        [
            "'><script>alert(document.cookie)</script>",
            "javascript://%0aalert(1)",
            "data://text/html,x",
            'openid-credential-offer://"onmouseover=x',
            "openid-credential-offer:// x",
            "no-scheme",
            "",
            None,
        ],
    )
    def test_dangerous_prefixes_rejected(self, prefix):
        from app.services.credential_offer import is_valid_offer_prefix

        assert not is_valid_offer_prefix(prefix)

    def test_route_rejects_script_prefix(self):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        with patch_configuration(json.loads(json.dumps(CONFIG))), patch.dict(
            oidc_routes.oidc_metadata, {"credential_configurations_supported": {"pid": {}}}
        ), patch.object(oidc_routes, "post_redirect_with_payload") as page:
            response = app.test_client().post(
                "/credential_offer",
                data={
                    "proceed": "1",
                    "credential_offer_URI": "'><script>alert(document.domain)</script><x x='",
                    "Authorization Code Grant": "auth_code",
                    "pid": "on",
                },
            )
        assert response.status_code == 400
        page.assert_not_called()


class TestSecurityHeaders:
    """No CSP was set on the backend origin."""

    def test_csp_and_referrer_policy(self, monkeypatch):
        from app.factory import create_app

        monkeypatch.setattr(
            "app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc")
        )
        config = {
            "service_url": "https://backend.test/",
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test/app"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
        }
        with patch_configuration(config):
            app = create_app(test_config={"TESTING": True, "SECRET_KEY": "k"})
            headers = app.test_client().get("/").headers
        csp = headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "form-action https://fe.test;" in csp
        assert "script-src 'sha256-" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
        assert headers["Referrer-Policy"] == "no-referrer"


class TestSessionSigningKey:
    """SECRET_KEY='dev' let anyone forge session cookies."""

    @pytest.fixture
    def factory_config(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc")
        )
        return {
            "service_url": "https://backend.test/",
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
        }

    @pytest.mark.parametrize("key", [None, "dev", "change-me", "short"])
    def test_production_refuses_weak_or_missing_key(self, factory_config, monkeypatch, key):
        from app.factory import create_app

        monkeypatch.setattr("app.core.config.IS_TEST_ENV", False)
        monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
        if key:
            factory_config["secret_key"] = key
        with patch_configuration(factory_config), patch("app.factory._start_background_services"), patch(
            "app.services.metadata.setup_trusted_cas"
        ), pytest.raises(RuntimeError, match="secret_key"):
            create_app()

    def test_production_uses_configured_key(self, factory_config, monkeypatch):
        from app.factory import create_app

        monkeypatch.setattr("app.core.config.IS_TEST_ENV", False)
        factory_config["secret_key"] = "k" * 40
        with patch_configuration(factory_config), patch("app.factory._start_background_services"), patch(
            "app.services.metadata.setup_trusted_cas"
        ):
            app = create_app()
        assert app.config["SECRET_KEY"] == "k" * 40


class TestPlaceholderApiKey:
    """The example configuration shipped backend_api_key: "change-me"."""

    @pytest.mark.parametrize("key", ["change-me", "secret", ""])
    def test_placeholder_key_is_treated_as_unset(self, key):
        from app.core.security import configured_api_key, is_valid_api_key

        with patch_configuration({"backend_api_key": key}):
            assert configured_api_key() is None
            assert not is_valid_api_key(key)


class TestPresentationReplayAndIdor:
    """AUTH-VULN-06 (static OID4VP nonce) and the cross-device presentation_id IDOR."""

    VERIFIER_CONFIG = {
        "dynamic_presentation_url": "https://verifier.test/ui/presentations",
        "oid4vp_scheme": "eudi-openid4vp://",
        "intended_use_id": "use",
    }

    def test_each_presentation_gets_a_fresh_nonce(self):
        from app.services import oid4vp as oid4vp_service

        responses = [{"transaction_id": f"t{i}", "client_id": "c", "request_uri": "r"} for i in range(4)]
        with patch_configuration(self.VERIFIER_CONFIG), patch.object(oid4vp_service.requests, "request") as http:
            http.return_value.json.side_effect = responses
            first = oid4vp_service.start_presentation({"credentials": []}, "https://b.test/cb")
            second = oid4vp_service.start_presentation({"credentials": []}, "https://b.test/cb")
        sent = [json.loads(call.kwargs["data"])["nonce"] for call in http.call_args_list]
        assert sent == [first.nonce, first.nonce, second.nonce, second.nonce]
        assert first.nonce != second.nonce and len(first.nonce) >= 43
        assert "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=" not in sent

    def test_foreign_presentation_id_is_not_fetched_by_pid_login(self):
        from app.routes import oid4vp as oid4vp_routes
        from app.routes.oid4vp import oid4vp

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oid4vp)
        session = _session(oid4vp_transaction_id="mine-same", oid4vp_cross_device_id="mine-cross")
        with patch_configuration({**CONFIG, **self.VERIFIER_CONFIG}), patch.object(
            oid4vp_routes.session_manager, "get_session", return_value=session
        ), patch.object(oid4vp_routes, "fetch_presentation_result") as fetch:
            client = app.test_client()
            with client.session_transaction() as s:
                s["session_id"] = "s1"
            response = client.get("/getpidoid4vp?presentation_id=victim-transaction")
        assert response.status_code == 400
        fetch.assert_not_called()

    def test_foreign_presentation_id_is_not_fetched_by_revocation(self):
        from app.routes import revocation as revocation_routes

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(revocation_routes.revocation)
        with patch_configuration({**CONFIG, **self.VERIFIER_CONFIG}), patch.object(
            revocation_routes, "fetch_presentation_result"
        ) as fetch:
            client = app.test_client()
            with client.session_transaction() as s:
                s["session_id"] = "s1"
                s["oid4vp_cross_device_id"] = "mine-cross"
            response = client.get("/revocation/getoid4vp?presentation_id=victim-transaction")
            no_request = client.get("/revocation/getoid4vp?response_code=x&session_id=s1")
        assert response.status_code == 400 and no_request.status_code == 400
        fetch.assert_not_called()

    def test_own_cross_device_transaction_is_fetched(self):
        from app.services.oid4vp import result_url_from_request

        with patch_configuration(self.VERIFIER_CONFIG):
            url = result_url_from_request({"presentation_id": "mine-cross"}, "mine-same", "mine-cross")
            same = result_url_from_request({"response_code": "rc&x", "session_id": "s1"}, "mine-same", "mine-cross")
        assert url == "https://verifier.test/ui/presentations/mine-cross"
        assert same == "https://verifier.test/ui/presentations/mine-same?response_code=rc%26x"


class TestPidPresentationChecks:
    """The PID login accepted any document type and expired document signers."""

    def _token(self, documents):
        import cbor2

        return {"vp_token": {"query_0": [base64.urlsafe_b64encode(cbor2.dumps({"status": 0, "documents": documents})).decode()]}}

    @pytest.mark.parametrize(
        "documents",
        [[], [{"docType": "org.iso.18013.5.1.mDL"}], [{"docType": "eu.europa.ec.eudi.pid.1"}, {"docType": "eu.europa.ec.eudi.pid.1"}]],
    )
    def test_only_a_single_pid_document_is_accepted(self, documents):
        from app.services import vp_validation

        with patch.object(vp_validation, "validate_certificate", return_value=(True, "")) as check:
            is_error, _ = vp_validation.validate_vp_token(self._token(documents), [])
        assert is_error
        check.assert_not_called()


class TestSessionFixation:
    """AUTH-VULN-01 / AUTHZ-VULN-01: /auth_choice took session_id from the query string."""

    @pytest.fixture
    def as_key(self, tmp_path):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": "as-1", "use": "sig", "alg": "ES256"})
        path = tmp_path / "as_jwks.json"
        path.write_text(json.dumps({"keys": [jwk]}))
        return key, str(path)

    @pytest.fixture
    def oidc_client(self, as_key):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        config = json.loads(json.dumps(CONFIG))
        config["authorization_server"]["jwks_path"] = as_key[1]
        config["credential_auth_methods"] = {"PID_login": [], "country_selection": ["pid"]}
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        with patch_configuration(config), patch.object(oidc_routes, "session_manager") as sessions:
            sessions.get_session.return_value = None
            yield app.test_client(), sessions

    def _token(self, key, **overrides):
        import time

        import jwt

        claims = {
            "session_id": "as-session",
            "authorization_details": [{"type": "openid_credential", "credential_configuration_id": "pid"}],
            "aud": ["eudiw-issuer-backend"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            **overrides,
        }
        return jwt.encode(claims, key, algorithm="ES256", headers={"kid": "as-1"})

    def test_session_comes_from_the_signed_token(self, oidc_client, as_key):
        client, sessions = oidc_client
        response = client.get(
            "/auth_choice",
            query_string={"token": "jws", "session_token": self._token(as_key[0]), "session_id": "attacker-chosen"},
        )
        assert response.status_code == 302
        assert sessions.add_session.call_args.kwargs["session_id"] == "as-session"
        with client.session_transaction() as s:
            assert s["session_id"] == "as-session"

    @pytest.mark.parametrize(
        "case",
        ["missing", "other_key", "expired", "wrong_audience", "no_session_id", "query_params_only"],
    )
    def test_untrusted_session_rejected(self, oidc_client, as_key, case):
        import time

        from cryptography.hazmat.primitives.asymmetric import ec

        client, sessions = oidc_client
        key = as_key[0]
        tokens = {
            "missing": None,
            "other_key": lambda: self._token(ec.generate_private_key(ec.SECP256R1())),
            "expired": lambda: self._token(key, iat=int(time.time()) - 900, exp=int(time.time()) - 600),
            "wrong_audience": lambda: self._token(key, aud=["someone-else"]),
            "no_session_id": lambda: self._token(key, session_id=""),
            "query_params_only": None,
        }
        token = tokens[case]() if tokens[case] else None
        query = {"token": "jws", "session_id": "victim", "authorization_details": json.dumps(json.dumps([{"credential_configuration_id": "pid"}]))}
        if token:
            query["session_token"] = token
        response = client.get("/auth_choice", query_string=query)
        assert response.status_code == 400
        sessions.add_session.assert_not_called()

    def test_existing_session_of_another_browser_rejected(self, oidc_client, as_key):
        client, sessions = oidc_client
        sessions.get_session.return_value = _session(session_id="as-session")
        response = client.get("/auth_choice", query_string={"token": "jws", "session_token": self._token(as_key[0])})
        assert response.status_code == 400
        sessions.add_session.assert_not_called()

    def test_same_browser_may_reload(self, oidc_client, as_key):
        client, sessions = oidc_client
        sessions.get_session.return_value = _session(session_id="as-session")
        with client.session_transaction() as s:
            s["session_id"] = "as-session"
        response = client.get("/auth_choice", query_string={"token": "jws", "session_token": self._token(as_key[0])})
        assert response.status_code == 302

    def test_preauth_code_request_sends_api_key(self):
        from app.services import auth_server

        config = {"authorization_server": {"base_url": "https://as.test", "api_key": "as-key"}}
        with patch_configuration(config), patch.object(auth_server.requests, "request") as http:
            http.return_value.json.return_value = {"session_id": "s"}
            auth_server.generate_preauth_code("pid")
        assert http.call_args.kwargs["headers"]["X-Api-Key"] == "as-key"
        http.return_value.raise_for_status.assert_called_once()


class TestCredentialTypeAuthorization:
    """A token authorized for credential A could obtain credential B."""

    @pytest.fixture
    def credential_client(self):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        session = _session(
            credentials_requested=["pid"],
            scope=None,
            authorization_details=[{"type": "openid_credential", "credential_configuration_id": "pid"}],
        )
        with patch_configuration(json.loads(json.dumps(CONFIG))), patch.object(
            oidc_routes, "verify_introspection", return_value=("s1", None)
        ), patch.object(oidc_routes, "session_manager") as sessions, patch.object(
            oidc_routes, "generate_credentials", return_value={"credentials": [{"credential": "c"}]}
        ) as generate, patch.object(oidc_routes, "vct2id", return_value=None), patch.object(
            oidc_routes, "_finish", side_effect=lambda session_id, response, *a: (response, 200)
        ):
            sessions.get_session.return_value = session
            yield app.test_client(), generate

    def _request(self, client, configuration_id):
        return client.post(
            "/credential",
            headers={"Authorization": "Bearer tok"},
            json={"credential_configuration_id": configuration_id, "proof": {"proof_type": "jwt", "jwt": "x"}},
        )

    def test_other_credential_rejected(self, credential_client):
        client, generate = credential_client
        response = self._request(client, "eu.europa.ec.eudi.mdl_mdoc")
        assert response.status_code == 400
        assert response.get_json()["error"] == "unknown_credential_configuration"
        generate.assert_not_called()

    def test_authorized_credential_issued(self, credential_client):
        client, generate = credential_client
        response = self._request(client, "pid")
        assert response.status_code == 200
        generate.assert_called_once()

    def test_credential_identifier_only_request_is_handled(self, credential_client):
        client, generate = credential_client
        response = client.post(
            "/credential",
            headers={"Authorization": "Bearer tok"},
            json={"credential_identifier": "pid", "proof": {"proof_type": "jwt", "jwt": "x"}},
        )
        assert response.status_code == 200
        assert generate.call_args.kwargs["credential_request"]["credential_configuration_id"] == "pid"


class TestIdpRedirectState:
    """AUTH-VULN-05: /dynamic/redirect accepted any code without checking state."""

    @pytest.fixture
    def redirect_client(self, client):
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session(country="OO")), patch.object(
            dynamic_routes, "exchange_authorization_code", return_value="at"
        ) as exchange, patch.object(dynamic_routes, "collect_user_data", return_value={}), patch.object(
            dynamic_routes, "presentation_formatter", return_value={}
        ), patch.object(dynamic_routes, "post_redirect_with_payload", return_value="consent"), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ):
            yield client, exchange

    @pytest.mark.parametrize("stored, sent", [(None, "x"), ("expected", None), ("expected", "attacker"), ("expected", "")])
    def test_wrong_or_missing_state_rejected(self, redirect_client, stored, sent):
        client, exchange = redirect_client
        with client.session_transaction() as s:
            if stored:
                s["oauth_state"] = stored
        query = {"code": "attacker-code"}
        if sent is not None:
            query["state"] = sent
        response = client.get("/dynamic/redirect", query_string=query)
        assert response.status_code == 400
        exchange.assert_not_called()

    def test_matching_state_accepted_once(self, redirect_client):
        client, exchange = redirect_client
        with client.session_transaction() as s:
            s["oauth_state"] = "expected"
        assert client.get("/dynamic/redirect", query_string={"code": "c", "state": "expected"}).status_code == 200
        assert client.get("/dynamic/redirect", query_string={"code": "c", "state": "expected"}).status_code == 400
        exchange.assert_called_once()


class TestLogsExactMatch:
    """AUTH-VULN-03: /logs?session_id=<any substring> returned every user's log lines."""

    SESSION = "0c6f8a52-1b2c-4d3e-8f90-123456789abc"
    OTHER = "9d1e2f30-4a5b-4c6d-8e7f-abcdefabcdef"

    @pytest.fixture
    def logs_client(self, tmp_path):
        from app.routes.oidc import oidc

        log = tmp_path / "backend.log"
        log.write_text(
            f"INFO | , Session ID: {self.SESSION}, Authorization selection\n"
            f"INFO | , Session ID: {self.OTHER}, form_data: given_name Doris\n"
            f"INFO | , Session ID: {self.SESSION}x, lookalike\n"
        )
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        config = {"backend_api_key": "k" * 40, "logging": {"backend_path": str(log)}}
        with patch_configuration(config):
            yield app.test_client()

    @pytest.mark.parametrize("probe", ["Session ID:", " ", "INFO", "given_name", "form_data", "a", SESSION[:8]])
    def test_substrings_rejected(self, logs_client, probe):
        response = logs_client.get("/logs", query_string={"session_id": probe}, headers={"X-Api-Key": "k" * 40})
        assert response.status_code == 400

    def test_only_the_exact_session_is_returned(self, logs_client):
        body = logs_client.get(
            "/logs", query_string={"session_id": self.SESSION}, headers={"X-Api-Key": "k" * 40}
        ).get_json()
        assert body["count"] == 1 and "Doris" not in json.dumps(body) and "lookalike" not in json.dumps(body)


class TestMetadataSigner:
    """AUTHZ-VULN-08 residue: caller metadata overrode sub/iat; errors leaked details."""

    def test_metadata_cannot_override_registered_claims(self, monkeypatch):
        import jwt
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        import datetime

        from app.services import metadata as metadata_service

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fe")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        frontend = {
            "url": "https://fe.test",
            "metadata_signing_key": key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
            "metadata_signing_key_password": None,
            "metadata_access_certificate": cert.public_bytes(serialization.Encoding.PEM),
        }
        monkeypatch.setattr(metadata_service, "frontend_config", lambda _id: frontend)
        token = metadata_service.sign_issuer_metadata(
            {"sub": "https://attacker.example", "iat": 1, "exp": 1, "credential_issuer": "https://fe.test"}, "fe"
        )
        claims = jwt.decode(token, options={"verify_signature": False})
        assert claims["sub"] == "https://fe.test" and claims["iat"] > 1 and "exp" not in claims
        assert claims["credential_issuer"] == "https://fe.test"

    def test_errors_do_not_leak_details(self):
        from app.routes import metadata as metadata_routes
        from app.routes.metadata import metadata
        from app.services.metadata import MetadataSigningError

        app = Flask(__name__)
        app.config.update(TESTING=True)
        app.register_blueprint(metadata)
        config = {"backend_api_key": "k" * 40, "frontend": {"frontends_config": {"fe": {}}}}
        with patch_configuration(config), patch.object(
            metadata_routes, "sign_issuer_metadata",
            side_effect=MetadataSigningError("Failed to load private key", "/etc/eudiw/keys/fe.key: bad password"),
        ):
            response = app.test_client().post(
                "/metadata/metadata_signer",
                json={"metadata": {"a": 1}, "issuer_frontend_id": "fe"},
                headers={"X-Api-Key": "k" * 40},
            )
        assert response.status_code == 500 and "/etc/eudiw" not in response.get_data(as_text=True)


class TestFormIndexDos:
    """x[9999999999]=1 made the form parser append billions of list items."""

    def test_huge_index_rejected_quickly(self):
        import time

        from app.services.presentation import InvalidFormError, _set_nested

        start = time.monotonic()
        with pytest.raises(InvalidFormError):
            _set_nested({}, "x[9999999999]", "1")
        with pytest.raises(InvalidFormError):
            _set_nested({}, "x[9999999999][y]", "1")
        assert time.monotonic() - start < 1

    def test_normal_indices_still_work(self):
        from app.services.presentation import _set_nested

        target = {}
        _set_nested(target, "capacities[1][code]", "A")
        assert target == {"capacities": [{}, {"code": "A"}]}

    def test_route_returns_400(self, client, config):
        config["test_features"] = {"form_countries": True}
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()), patch.object(
            dynamic_routes.session_manager, "update_user_data"
        ) as store:
            response = client.post("/dynamic/form", data={"proceed": "1", "x[9999999999]": "1"})
        assert response.status_code == 400
        store.assert_not_called()


class TestRevocationBinding:
    """AUTH-VULN-13: anyone holding a revocation_identifier could revoke."""

    @pytest.fixture
    def revoke_client(self):
        import datetime as dt

        from app.routes import revocation as revocation_routes

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(revocation_routes.revocation)
        pending = {
            "victim-revocation": {
                "status_lists": {"dc+sd-jwt": [{"status_list": {"idx": 1, "uri": "https://sl.test/1"}}], "mso_mdoc": []},
                "expires": dt.datetime.now() + dt.timedelta(minutes=5),
            },
            "expired": {"status_lists": {}, "expires": dt.datetime.now() - dt.timedelta(seconds=1)},
        }
        with patch_configuration(json.loads(json.dumps(CONFIG))), patch.object(
            revocation_routes, "revocation_requests", pending
        ), patch.object(revocation_routes, "set_token_status", return_value=1) as set_status, patch.object(
            revocation_routes, "post_redirect_with_payload", return_value="done"
        ):
            yield app.test_client(), set_status, pending

    def test_identifier_of_another_session_rejected(self, revoke_client):
        client, set_status, pending = revoke_client
        response = client.post("/revocation/revoke", data={"revocation_identifier": "victim-revocation"})
        assert response.status_code == 403
        set_status.assert_not_called()
        assert "victim-revocation" in pending

    def test_expired_request_rejected(self, revoke_client):
        client, set_status, _ = revoke_client
        with client.session_transaction() as s:
            s["revocation_id"] = "expired"
        assert client.post("/revocation/revoke", data={"revocation_identifier": "expired"}).status_code == 404
        set_status.assert_not_called()

    def test_own_request_revoked_once(self, revoke_client):
        client, set_status, _ = revoke_client
        with client.session_transaction() as s:
            s["revocation_id"] = "victim-revocation"
        assert client.post("/revocation/revoke", data={"revocation_identifier": "victim-revocation"}).status_code == 200
        assert client.post("/revocation/revoke", data={"revocation_identifier": "victim-revocation"}).status_code == 403
        set_status.assert_called_once()


class TestX5cTrust:
    """Key-attestation / offer-request chains: any alg was accepted; a leaf could act as a CA."""

    @pytest.fixture
    def pki(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        from app.core import state
        from pki_helpers import ca_entry, make_cert

        root_key, mid_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
        root = make_cert("Root CA", "Root CA", root_key.public_key(), root_key, ca=True)
        leaf_as_ca = make_cert("Not a CA", "Root CA", mid_key.public_key(), root_key, ca=False)
        leaf = make_cert("Signer", "Not a CA", leaf_key.public_key(), mid_key, ca=False)
        with patch.dict(state.trusted_CAs, {root.subject: ca_entry(root)}, clear=True):
            yield {"root": root, "leaf_as_ca": leaf_as_ca, "leaf": leaf, "root_key": root_key, "leaf_key": leaf_key}

    def test_leaf_certificate_cannot_issue(self, pki):
        from app.core.errors import CertificateVerificationError
        from app.services.trust import verify_chain_against_trusted_CAs
        from cryptography.hazmat.primitives import serialization

        der = [c.public_bytes(serialization.Encoding.DER) for c in (pki["leaf"], pki["leaf_as_ca"])]
        with pytest.raises(CertificateVerificationError, match="not a CA"):
            verify_chain_against_trusted_CAs(der)

    @pytest.mark.parametrize("alg", ["none", "HS256"])
    def test_symmetric_or_none_alg_rejected_by_default(self, alg):
        from app.services.trust import _x5c_header

        header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "x5c": ["AA=="]}).encode()).rstrip(b"=").decode()
        with pytest.raises(ValueError, match="not allowed"):
            _x5c_header(f"{header}.e30.", None)

    @pytest.mark.parametrize(
        "claims",
        [{}, {"iat": 1}, {"exp": 4102444800}, {"iat": 1700000000, "exp": 1700000000 + 86400}],
    )
    def test_offer_request_needs_short_lived_exp_and_iat(self, client, pki, claims):
        import time

        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import ec

        from pki_helpers import make_cert, x5c

        if "exp" in claims and claims["exp"] < time.time():
            claims = {"iat": int(time.time()), "exp": int(time.time()) + 86400}
        signer = make_cert("Requester", "Root CA", pki["leaf_key"].public_key(), pki["root_key"], ca=False)
        token = pyjwt.encode(
            {"credentials": [{"credential_configuration_id": "pid", "data": {}}], **claims},
            pki["leaf_key"],
            algorithm="ES256",
            headers={"x5c": x5c(signer)},
        )
        with patch.object(preauth_routes, "request_preauth_token") as start:
            response = client.post("/credentialOfferReq2", data={"request": token})
        assert response.status_code == 401
        start.assert_not_called()


class TestBrowserSessionEnds:
    """AUTH-VULN-11: the browser session stayed usable after the flow."""

    def test_session_cleared_on_hand_off_to_the_wallet(self, client, config):
        config["test_features"] = {"form_countries": True}
        with patch.object(dynamic_routes.session_manager, "get_session", return_value=_session()):
            response = client.post("/dynamic/redirect_wallet")
            assert response.status_code == 302
            with client.session_transaction() as s:
                assert "session_id" not in s
            # The same cookie cannot submit the form again (400, not a 500).
            assert client.post("/dynamic/form", data={"proceed": "1", "family_name": "x"}).status_code == 400
            assert client.post("/dynamic/redirect_wallet").status_code == 400


class TestRateLimits:
    """AUTH-VULN-04: no endpoint was rate limited."""

    def _app(self, monkeypatch, **settings):
        from app.factory import create_app

        monkeypatch.setattr(
            "app.services.metadata._build_credential_encryption_metadata", MagicMock(return_value="enc")
        )
        config = {
            "service_url": "https://backend.test/",
            "backend_api_key": "k" * 40,
            "frontend": {"default": "fe", "frontends_config": {"fe": {"url": "https://fe.test"}}},
            "keys": {"credential_encryption_key": b"Key_Sample"},
            "logging": {"backend_path": "/tmp/log/fakepath.log", "log_level": "INFO"},
            "rate_limiting": settings,
        }
        with patch_configuration(config):
            return create_app(test_config={"TESTING": True, "SECRET_KEY": "k" * 40}), config

    def test_logs_endpoint_throttled(self, monkeypatch):
        app, config = self._app(monkeypatch, limits={"oidc.get_logs_by_session": "3 per minute"})
        client = app.test_client()
        with patch_configuration(config):
            codes = [client.get("/logs?session_id=x", headers={"X-Api-Key": "k" * 40}).status_code for _ in range(5)]
        assert codes[:3] == [400, 400, 400] and codes[3:] == [429, 429]

    def test_limits_are_per_client_behind_a_proxy(self, monkeypatch):
        app, config = self._app(monkeypatch, trusted_proxies=1, limits={"oidc.get_logs_by_session": "1 per minute"})
        client = app.test_client()
        headers = {"X-Api-Key": "k" * 40}
        with patch_configuration(config):
            first = client.get("/logs?session_id=x", headers={**headers, "X-Forwarded-For": "198.51.100.1"})
            again = client.get("/logs?session_id=x", headers={**headers, "X-Forwarded-For": "198.51.100.1"})
            other = client.get("/logs?session_id=x", headers={**headers, "X-Forwarded-For": "198.51.100.2"})
        assert (first.status_code, again.status_code, other.status_code) == (400, 429, 400)

    def test_can_be_disabled(self, monkeypatch):
        app, config = self._app(monkeypatch, enabled=False, limits={"oidc.get_logs_by_session": "1 per minute"})
        client = app.test_client()
        with patch_configuration(config):
            codes = {client.get("/logs?session_id=x", headers={"X-Api-Key": "k" * 40}).status_code for _ in range(3)}
        assert codes == {400}


class TestDpopAtResourceEndpoints:
    """AUTH-VULN-07: a DPoP-bound token replayed as a Bearer token was accepted."""

    TOKEN = "access-token-value"

    @pytest.fixture
    def wallet_key(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1())

    def _jkt(self, key):
        import jwt as pyjwt

        from app.services.dpop import jwk_thumbprint

        return jwk_thumbprint(json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key())))

    def _proof(self, key, htu="https://backend.test/credential", htm="POST", token=None, **extra):
        import hashlib
        import time
        import uuid

        import jwt as pyjwt

        claims = {
            "jti": str(uuid.uuid4()),
            "htm": htm,
            "htu": htu,
            "iat": int(time.time()),
            "ath": base64.urlsafe_b64encode(hashlib.sha256((token or self.TOKEN).encode()).digest()).rstrip(b"=").decode(),
            **extra,
        }
        public = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        return pyjwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public})

    @pytest.fixture
    def credential_client(self, wallet_key):
        from app.routes import oidc as oidc_routes
        from app.routes.oidc import oidc

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test")
        app.register_blueprint(oidc)
        config = json.loads(json.dumps(CONFIG))
        config["status_validator"] = {"enabled": False}
        introspection = MagicMock()
        introspection.json.return_value = {"active": True, "username": "s1", "cnf": {"jkt": self._jkt(wallet_key)}}
        with patch_configuration(config), patch.object(oidc_routes, "introspect", return_value=introspection), patch.object(
            oidc_routes, "session_manager"
        ) as sessions, patch.object(
            oidc_routes, "generate_credentials", return_value={"credentials": [{"credential": "c"}]}
        ) as generate, patch.object(oidc_routes, "vct2id", return_value=None), patch.object(
            oidc_routes, "_finish", side_effect=lambda session_id, response, *a: (response, 200)
        ):
            sessions.get_session.return_value = _session(credentials_requested=["pid"], scope=None)
            yield app.test_client(), generate

    def _post(self, client, headers):
        return client.post("/credential", headers=headers, json={"credential_configuration_id": "pid", "proof": {"proof_type": "jwt", "jwt": "x"}})

    def test_bearer_replay_rejected(self, credential_client):
        client, generate = credential_client
        response = self._post(client, {"Authorization": f"Bearer {self.TOKEN}"})
        assert response.status_code == 401 and response.get_json()["error"] == "invalid_dpop_proof"
        generate.assert_not_called()

    def test_valid_proof_accepted(self, credential_client, wallet_key):
        client, generate = credential_client
        response = self._post(client, {"Authorization": f"DPoP {self.TOKEN}", "DPoP": self._proof(wallet_key)})
        assert response.status_code == 200
        generate.assert_called_once()

    @pytest.mark.parametrize("variant", ["other_key", "wrong_htu", "wrong_htm", "wrong_ath", "missing", "replayed"])
    def test_invalid_proofs_rejected(self, credential_client, wallet_key, variant):
        from cryptography.hazmat.primitives.asymmetric import ec

        client, generate = credential_client
        proofs = {
            "other_key": lambda: self._proof(ec.generate_private_key(ec.SECP256R1())),
            "wrong_htu": lambda: self._proof(wallet_key, htu="https://backend.test/notification"),
            "wrong_htm": lambda: self._proof(wallet_key, htm="GET"),
            "wrong_ath": lambda: self._proof(wallet_key, token="another-token"),
            "missing": lambda: None,
            "replayed": lambda: self._proof(wallet_key, jti="same-jti"),
        }
        proof = proofs[variant]()
        headers = {"Authorization": f"DPoP {self.TOKEN}"}
        if proof:
            headers["DPoP"] = proof
        if variant == "replayed":
            assert self._post(client, headers).status_code == 200
            generate.reset_mock()
        response = self._post(client, headers)
        assert response.status_code == 401
        generate.assert_not_called()

    def test_introspection_sends_api_key(self):
        from app.services import auth_server

        with patch_configuration({"authorization_server": {"base_url": "https://as.test", "api_key": "as-key"}}), patch.object(
            auth_server.requests, "request"
        ) as http:
            auth_server.introspect("tok")
        assert http.call_args.kwargs["headers"]["X-Api-Key"] == "as-key"
        assert http.call_args.kwargs["data"] == {"token": "tok"}



class TestSessionRepr:
    """Pre-authorized codes and tx_codes could end up in logs via repr()."""

    def test_secrets_are_masked(self):
        import datetime as dt

        from app.repositories.session_store import Session

        session = Session(
            session_id="s1",
            expiry_time=dt.datetime.now(dt.timezone.utc),
            pre_authorized_code="secret-code",
            tx_code=12345,
            user_data={"family_name": "Doe"},
            country="FC",
        )
        text = repr(session)
        assert "secret-code" not in text and "12345" not in text and "Doe" not in text
        assert "tx_code=<set>" in text and "country='FC'" in text

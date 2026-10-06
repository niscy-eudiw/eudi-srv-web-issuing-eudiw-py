"""Tests for loading and processing the issuer YAML configuration."""

import sys

import pytest
import yaml

from app.core import config


def _write(path, content: bytes) -> str:
    path.write_bytes(content)
    return str(path)


@pytest.fixture
def config_files(tmp_path):
    """A minimal valid configuration whose key / certificate paths exist."""
    files = {
        "fe_key": _write(tmp_path / "fe.key", b"FE-KEY"),
        "fe_cert": _write(tmp_path / "fe.crt", b"FE-CERT"),
        "nonce": _write(tmp_path / "nonce.pem", b"NONCE-KEY"),
        "enc": _write(tmp_path / "enc.pem", b"ENC-KEY"),
        "fc_key": _write(tmp_path / "fc.pem", b"FC-KEY"),
        "fc_cert": _write(tmp_path / "fc.der", b"FC-CERT"),
        "fe_fc_key": _write(tmp_path / "fe-fc.pem", b"FE-FC-KEY"),
        "fe_fc_cert": _write(tmp_path / "fe-fc.der", b"FE-FC-CERT"),
    }
    data = {
        "service_url": "https://backend.test",
        "frontend": {
            "default": "fe1",
            "frontends_config": {
                "fe1": {
                    "url": "https://frontend.test",
                    "metadata_signing_key_path": files["fe_key"],
                    "metadata_access_certificate_path": files["fe_cert"],
                }
            },
        },
        "keys": {"nonce_path": files["nonce"], "credential_request_path": files["enc"]},
        "countries": {
            "FC": {
                "keys": {
                    "_default": {"private_key_path": files["fc_key"], "certificate_path": files["fc_cert"]},
                    "fe1": {"private_key_path": files["fe_fc_key"], "certificate_path": files["fe_fc_cert"]},
                }
            }
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data))
    return config_path


class TestLoadConfig:
    def test_valid_file_is_processed(self, config_files):
        loaded = config.load_config(str(config_files))

        frontend = loaded["frontend"]["frontends_config"]["fe1"]
        assert frontend["metadata_signing_key"] == b"FE-KEY"
        assert frontend["metadata_access_certificate"] == b"FE-CERT"
        assert loaded["keys"]["nonce_key"] == b"NONCE-KEY"
        assert loaded["keys"]["credential_encryption_key"] == b"ENC-KEY"
        country_keys = loaded["countries"]["FC"]["keys"]
        assert (country_keys["_default"]["private_key"], country_keys["_default"]["certificate"]) == (
            b"FC-KEY",
            b"FC-CERT",
        )
        assert country_keys["fe1"]["private_key"] == b"FE-FC-KEY"
        # Paths are kept next to the loaded bytes.
        assert country_keys["_default"]["private_key_path"].endswith("fc.pem")

    def test_path_from_environment(self, config_files, monkeypatch):
        monkeypatch.setenv("ISSUER_CONFIG_PATH", str(config_files))
        assert config.load_config()["service_url"] == "https://backend.test"

    def test_default_path_used_without_environment(self, monkeypatch):
        monkeypatch.delenv("ISSUER_CONFIG_PATH", raising=False)
        with pytest.raises(RuntimeError, match=config.DEFAULT_CONFIG_PATH):
            config.load_config()

    def test_missing_file(self, tmp_path):
        with pytest.raises(RuntimeError, match="Config file not found"):
            config.load_config(str(tmp_path / "nope.yaml"))

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        with pytest.raises(RuntimeError, match="Config file is empty"):
            config.load_config(str(empty))

    def test_invalid_yaml(self, tmp_path):
        broken = tmp_path / "broken.yaml"
        broken.write_text("service_url: [unclosed")
        with pytest.raises(RuntimeError, match="Invalid YAML"):
            config.load_config(str(broken))

    def test_missing_key_file(self, config_files, tmp_path):
        data = yaml.safe_load(config_files.read_text())
        data["keys"]["nonce_path"] = str(tmp_path / "missing.pem")
        config_files.write_text(yaml.safe_dump(data))

        with pytest.raises(OSError):
            config.load_config(str(config_files))

    def test_missing_section(self, tmp_path):
        partial = tmp_path / "partial.yaml"
        partial.write_text(yaml.safe_dump({"service_url": "x"}))
        with pytest.raises(KeyError):
            config.load_config(str(partial))


def test_mock_config_shape():
    mocked = config.mock_config()
    assert mocked["expiry"]["session"] == 30
    assert set(mocked["postgres"]) == {"host", "port", "dbname", "user", "password"}


class TestDetectTestEnv:
    @pytest.fixture(autouse=True)
    def _clean(self, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("SONARCLOUD", raising=False)
        monkeypatch.setattr(sys, "argv", ["flask", "run"])
        monkeypatch.delitem(sys.modules, "pytest")

    def test_production_like_process(self):
        assert config._detect_test_env() is False

    @pytest.mark.parametrize("variable", ["CI", "SONARCLOUD"])
    def test_ci_variables(self, monkeypatch, variable):
        monkeypatch.setenv(variable, "true")
        assert config._detect_test_env() is True

    def test_ci_variable_must_be_true(self, monkeypatch):
        monkeypatch.setenv("CI", "false")
        assert config._detect_test_env() is False

    def test_pytest_in_argv(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["/usr/bin/pytest", "-q"])
        assert config._detect_test_env() is True

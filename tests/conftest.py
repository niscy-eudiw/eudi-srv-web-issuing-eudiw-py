"""Shared pytest fixtures."""

import pytest

from config_helpers import set_configuration


@pytest.fixture(autouse=True)
def mock_configuration(monkeypatch):
    """Gives every test a minimal configuration in all app modules."""
    config = {"service_url": "https://service.test"}
    set_configuration(monkeypatch, config)
    yield config

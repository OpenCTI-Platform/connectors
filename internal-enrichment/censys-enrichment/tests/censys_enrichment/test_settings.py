"""Tests for censys_enrichment.settings (ConfigLoader field validation)."""

from typing import Any

import pytest
from censys_enrichment.settings import ConfigLoader
from connectors_sdk import ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "censys-enrichment--674403d0-4723-40cd-b03c-42fb959d5469",
                    "name": "Censys Enrichment",
                    "scope": "IPv4-Addr,IPv6-Addr,X509-Certificate,Domain-Name",
                    "log_level": "error",
                    "auto": True,
                },
                "censys_enrichment": {
                    "organisation_id": "my-org-id",
                    "token": "my-api-token",
                    "max_tlp": "TLP:AMBER",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "censys_enrichment": {
                    "organisation_id": "my-org-id",
                    "token": "my-api-token",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    class FakeConfigLoader(ConfigLoader):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    cfg = FakeConfigLoader()
    assert isinstance(cfg.to_helper_config(), dict)


def test_settings_should_reject_missing_required_fields():
    class FakeConfigLoader(ConfigLoader):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    # censys_enrichment.organisation_id and .token are required — omitted
                    "censys_enrichment": {},
                }
            )

    with pytest.raises((ConfigValidationError, Exception)):
        FakeConfigLoader()


def test_default_max_tlp_is_amber():
    class FakeConfigLoader(ConfigLoader):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "censys_enrichment": {
                        "organisation_id": "my-org-id",
                        "token": "my-api-token",
                    },
                }
            )

    cfg = FakeConfigLoader()
    assert cfg.censys_enrichment.max_tlp == "TLP:AMBER"


def test_default_nvd_enabled_is_true():
    class FakeConfigLoader(ConfigLoader):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "censys_enrichment": {
                        "organisation_id": "my-org-id",
                        "token": "my-api-token",
                    },
                }
            )

    cfg = FakeConfigLoader()
    assert cfg.censys_enrichment.nvd_enabled is True


def test_nvd_enabled_can_be_disabled():
    class FakeConfigLoader(ConfigLoader):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "censys_enrichment": {
                        "organisation_id": "my-org-id",
                        "token": "my-api-token",
                        "nvd_enabled": False,
                    },
                }
            )

    cfg = FakeConfigLoader()
    assert cfg.censys_enrichment.nvd_enabled is False

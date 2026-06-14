"""Parametrized settings validation tests for google-secops ConnectorSettings."""

from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from test_helpers import FULL_VALID_CONFIG, MINIMAL_VALID_CONFIG, make_stub_settings

# Minimal valid google_secops block — reused across parametrized cases
_SERVICE_ACCOUNT = {
    "project_id": "test-project",
    "project_region": "us",
    "project_instance": "test-instance-uuid",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
    "private_key_id": "key-id-1",
    "client_email": "sa@test.iam.gserviceaccount.com",
    "client_id": "123456789",
    "client_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sa%40test.iam.gserviceaccount.com",
}


# ===========================================================================
# BDD helpers
# ===========================================================================
def _given_settings_from(config_dict: dict[str, Any]):
    """Return a ConnectorSettings instance backed by *config_dict*."""
    return make_stub_settings(config_dict)()


def _when_instantiated(settings_cls_or_fn):
    """Instantiate a settings class or callable."""
    return settings_cls_or_fn()


def _then_sections_are_base_config_models(settings):
    """Assert all three config sections are BaseConfigModel instances."""
    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.google_secops_siem_incidents, BaseConfigModel)


def _then_raises_config_validation_error(config_dict: dict[str, Any]):
    """Assert that instantiation raises ConfigValidationError."""
    with pytest.raises(ConfigValidationError):
        make_stub_settings(config_dict)()


# ===========================================================================
# Valid settings — Scenarios 2 & 3
# ===========================================================================
@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_CONFIG, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_CONFIG, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """ConnectorSettings accepts a valid config dict and all sections are BaseConfigModel."""
    settings = _given_settings_from(settings_dict)
    _then_sections_are_base_config_models(settings)


# ===========================================================================
# Invalid settings — Scenarios 4-7
# ===========================================================================
@pytest.mark.parametrize(
    "settings_dict, error_hint",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "name": "Test Google SecOps",
                    "scope": "google-secops",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "google_secops_siem_incidents": _SERVICE_ACCOUNT
                | {"tlp_level": "clear"},
            },
            "connector.id",
            id="missing_connector_id",
        ),
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Google SecOps",
                    "scope": "google-secops",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "google_secops_siem_incidents": _SERVICE_ACCOUNT
                | {"tlp_level": "clear"},
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Google SecOps",
                    "scope": "google-secops",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "google_secops_siem_incidents": _SERVICE_ACCOUNT
                | {"tlp_level": "not-a-valid-tlp"},
            },
            "google_secops_siem_incidents.tlp_level",
            id="invalid_google_secops_tlp_level",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, error_hint):
    """ConnectorSettings raises ConfigValidationError on invalid input."""
    _then_raises_config_validation_error(settings_dict)


# ===========================================================================
# Defaults — Scenarios 8 & 9
# ===========================================================================
def test_connector_name_defaults_to_google_secops():
    """When connector name is not overridden, it defaults to 'Google SecOps'."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id", "scope": "google-secops"},
        "google_secops_siem_incidents": _SERVICE_ACCOUNT,
    }
    settings = _given_settings_from(config)
    assert settings.connector.name == "Google SecOps"


def test_connector_duration_period_defaults_to_pt1h():
    """When duration_period is not overridden, it defaults to PT1H (3600 seconds)."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id", "scope": "google-secops"},
        "google_secops_siem_incidents": _SERVICE_ACCOUNT,
    }
    settings = _given_settings_from(config)
    assert settings.connector.duration_period.total_seconds() == 3600.0


# ===========================================================================
# Field access — Scenarios 10 & 11
# ===========================================================================
def test_google_secops_config_exposes_service_account_fields():
    """GoogleSecOpsConfig exposes project_id and client_email."""
    settings = _given_settings_from(FULL_VALID_CONFIG)

    assert settings.google_secops_siem_incidents.project_id == "test-project"
    assert (
        settings.google_secops_siem_incidents.client_email
        == "sa@test.iam.gserviceaccount.com"
    )


def test_google_secops_tlp_level_defaults_to_amber():
    """GoogleSecOpsConfig.tlp_level defaults to 'amber' when not overridden."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id", "scope": "google-secops"},
        "google_secops_siem_incidents": _SERVICE_ACCOUNT,
    }
    settings = _given_settings_from(config)
    assert settings.google_secops_siem_incidents.tlp_level == "amber"

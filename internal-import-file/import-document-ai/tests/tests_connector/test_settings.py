from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from import_doc_ai.settings import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "ImportDocumentAI",
                    "scope": "application/pdf,text/plain,text/html,text/markdown",
                    "log_level": "error",
                    "validate_before_import": True,
                    "auto": False,
                    "xtm_one_intent": "cti.stix_harvester",
                },
                "import_document_ai": {
                    "include_relationships": True,
                    "create_indicator": False,
                    "api_base_url": "http://ariane.example",
                    "api_key": "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                },
                "import_document_ai": {},
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that ConnectorSettings accepts valid input.
    _load_config_dict is overridden to return a fake but valid dict.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.import_document_ai, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "ImportDocumentAI",
                    "scope": "application/pdf,text/plain,text/html,text/markdown",
                    "log_level": "error",
                },
                "import_document_ai": {},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": 12345,  # invalid: must be a string
                    "name": "ImportDocumentAI",
                    "scope": "application/pdf,text/plain,text/html,text/markdown",
                    "log_level": "error",
                },
                "import_document_ai": {},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that ConnectorSettings raises on invalid input.
    _load_config_dict is overridden to return a fake and invalid dict.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)

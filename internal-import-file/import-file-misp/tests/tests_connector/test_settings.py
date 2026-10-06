from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings


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
                    "name": "ImportFileMISP",
                    "scope": "application/json",
                    "log_level": "error",
                    "validate_before_import": True,
                    "auto": False,
                },
                "misp_import_file": {
                    "create_reports": True,
                    "report_type": "misp-event",
                    "create_indicators": True,
                    "create_observables": True,
                    "create_object_observables": False,
                    "create_tags_as_labels": True,
                    "guess_threats_from_tags": False,
                    "author_from_tags": False,
                    "markings_from_tags": False,
                    "import_to_ids_no_score": 40,
                    "import_unsupported_observables_as_text": False,
                    "import_unsupported_observables_as_text_transparent": True,
                    "import_with_attachments": False,
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
    assert isinstance(settings.misp_import_file, BaseConfigModel) is True


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
                    "name": "ImportFileMISP",
                    "scope": "application/json",
                    "log_level": "error",
                },
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
                    "id": 12345,
                    "name": "ImportFileMISP",
                    "scope": "application/json",
                    "log_level": "error",
                },
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

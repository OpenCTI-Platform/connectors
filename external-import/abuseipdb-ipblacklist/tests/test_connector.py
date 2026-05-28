from typing import Any
from unittest.mock import Mock

from external_import_connector import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from src.external_import_connector.connector import ConnectorAbuseIPDB


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "abuseipdb": {
                    "api_url": "https://api.abuseipdb.com/api/v2/blacklist",
                    "api_key": "test-api-key",
                    "score": 75,
                    "limit": 500000,
                    "create_indicator": False,
                    "tlp_level": "clear",
                    "ipversion": "mixed",
                    "except_country": [],
                    "only_country": [],
                },
            }
        )


def test_should_create_indicator_with_same_score():
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    connector = ConnectorAbuseIPDB(config=settings, helper=helper)

    connector.helper.api.work.initiate_work = lambda x, y: "work_id_123"

    connector.client.get_entities = Mock(
        return_value=[
            {
                "value": "8.8.8.8",
                "country_code": "US",
                "confidence_score": "95",
                "last_reported": "2024-01-01 00:00:00",
            },
        ]
    )

    def mocked_stix2_create_bundle(stix_objects):
        assert stix_objects[0].x_opencti_create_indicator

    connector.helper.stix2_create_bundle = mocked_stix2_create_bundle

    connector.process_message()

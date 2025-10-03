from unittest.mock import Mock, patch

from pycti import OpenCTIApiClient, OpenCTIApiConnector
from src.external_import_connector.config_variables import ConfigConnector
from src.external_import_connector.connector import ConnectorAbuseIPDB


@patch.dict(
    "os.environ",
    {
        "ABUSEIPDB_SCORE": "90",
        "ABUSEIPDB_CREATE_INDICATOR": "true",
    },
)
@patch.object(
    ConfigConnector,
    "_load_config",
    return_value={
        "opencti": {
            "url": "http://localhost:8080",
            "token": "changeme",
            "ssl_verify": False,
        },
        "connector": {
            "id": "CHANGEME",
            "name": "AbuseIPDB Connector",
            "type": "EXTERNAL_IMPORT",
        },
    },
)
@patch.object(
    OpenCTIApiClient,
    "health_check",
    return_value=True,
)
@patch.object(
    OpenCTIApiConnector,
    "ping",
    return_value={
        "id": "CHANGEME",
        "connector_user_id": "1",
        "connector_state": "{}",
    },
)
@patch.object(
    OpenCTIApiConnector,
    "register",
    return_value={
        "id": "CHANGEME",
        "connector_user_id": "1",
        "connector_state": "{}",
        "config": {
            "connection": {
                "host": "rabbitmq",
                "vhost": "/",
                "use_ssl": False,
                "port": 5672,
                "user": "opencti",
                "pass": "changeme",
            }
        },
    },
)
def test_should_create_indicator_with_same_score(_, __, ___, ____):
    connector = ConnectorAbuseIPDB()

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

    indictor_tag_exists = False

    def check_if_indicator_tag_exists(stix_objects):
        nonlocal indictor_tag_exists
        indictor_tag_exists = stix_objects[0].x_opencti_create_indicator

    connector.helper.stix2_create_bundle = Mock(
        side_effect=check_if_indicator_tag_exists
    )

    connector.process_message()

    assert indictor_tag_exists

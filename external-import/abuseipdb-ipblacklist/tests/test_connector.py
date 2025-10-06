from unittest.mock import Mock

from src.external_import_connector.connector import ConnectorAbuseIPDB


def test_should_create_indicator_with_same_score():
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

    def mocked_stix2_create_bundle(stix_objects):
        assert stix_objects[0].x_opencti_create_indicator

    connector.helper.stix2_create_bundle = mocked_stix2_create_bundle

    connector.process_message()

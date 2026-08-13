import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from connector import DatadogIntelConnector
from pydantic import SecretStr


def test_process_message_propagates_stream_event_type_to_validation_and_client():
    config = SimpleNamespace(
        datadog_intel=SimpleNamespace(
            indicator_type=["ip_address"],
            integration_api_url="http://test.com",
            dd_api_key=SecretStr("test-api-key"),
            dd_application_key=SecretStr("test-app-key"),
        )
    )
    helper = MagicMock()
    helper.connect_live_stream_id = "live"
    helper.connector_logger = MagicMock()
    connector = DatadogIntelConnector(config=config, helper=helper)
    client = MagicMock()
    connector.clients["ip_address"] = client

    expired_valid_until = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    msg = SimpleNamespace(
        event="delete",
        id="event-id",
        data=json.dumps(
            {
                "data": {
                    "type": "indicator",
                    "pattern_type": "stix",
                    "valid_until": expired_valid_until,
                    "modified": "2024-01-01T00:00:00Z",
                    "extensions": {
                        "ext-1": {
                            "id": "indicator--abc123",
                            "main_observable_type": "IPv4-Addr",
                        }
                    },
                }
            }
        ),
    )

    connector.process_message(msg)

    client.process_indicator.assert_called_once()
    processed_data = client.process_indicator.call_args.args[0]
    assert processed_data["event_type"] == "delete"
    assert processed_data["x_opencti_event_type"] == "delete"

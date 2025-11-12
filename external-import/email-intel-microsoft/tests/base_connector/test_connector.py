from unittest.mock import MagicMock, Mock

import freezegun
import pytest
import stix2
from base_connector import ConnectorError, ConnectorWarning
from base_connector.connector import BaseConnector

STIX_OBJECT = MagicMock()


class Connector(BaseConnector):
    def process_data(self) -> list[stix2.v21._STIXBase21]:
        return [STIX_OBJECT]


@pytest.fixture(name="connector")
def fixture_connector(mocked_helper: MagicMock) -> Connector:
    return Connector(
        helper=mocked_helper,
        config=Mock(),
        client=Mock(),
        converter=Mock(),
    )


@freezegun.freeze_time("2025-04-17T15:24:00Z")
def test_process(connector: Connector) -> None:
    connector.process()

    # Assert the work initiation and processing
    connector.helper.api.work.initiate_work.assert_called_once_with(
        connector_id="test-connector-id", friendly_name="Test Connector"
    )
    connector.helper.api.work.to_processed.assert_called_once_with(
        message="Connector successfully run", work_id="work-id"
    )

    # Assert the STIX object processing
    connector.helper.stix2_create_bundle.assert_called_once_with(
        items=[STIX_OBJECT, connector.converter.author, connector.converter.tlp_marking]
    )
    connector.helper.send_stix2_bundle.assert_called_once_with(
        bundle="bundle", cleanup_inconsistent_bundle=True, work_id="work-id"
    )


@pytest.mark.parametrize(
    "exception,expected",
    [
        (ConnectorWarning("Known warning"), "Known warning"),
        (ConnectorError("Known error"), "Known error"),
        (
            RuntimeError("Unknown error"),
            "Unexpected error. See connector logs for details.",
        ),
    ],
)
def test_process_catches_expected_errors(
    connector: Connector, mocker: MagicMock, exception: Exception, expected: str
) -> None:
    mocker.patch.object(connector, "process_message", side_effect=exception)
    assert connector.process() == expected

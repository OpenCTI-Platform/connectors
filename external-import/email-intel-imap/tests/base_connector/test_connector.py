import datetime
from unittest.mock import MagicMock, Mock

import freezegun
import stix2
from base_connector.connector import BaseConnector

STIX_OBJECT = MagicMock()


class TestConnector(BaseConnector):
    def collect_intelligence(
        self, last_run: datetime.datetime | None
    ) -> list[stix2.v21._STIXBase21]:
        return [STIX_OBJECT]


@freezegun.freeze_time("2025-04-17T15:24:00Z")
def test_process(mocked_helper: MagicMock) -> None:
    connector = TestConnector(
        helper=mocked_helper, config=Mock(), client=Mock(), converter=Mock()
    )
    connector.process_message()

    # Assert the work initiation and processing
    mocked_helper.api.work.initiate_work.assert_called_once_with(
        connector_id="test-connector-id", friendly_name="Test Connector"
    )
    mocked_helper.api.work.to_processed.assert_called_once_with(
        message="Connector successfully run, storing last_run as 2025-04-17 15:24:00+00:00",
        work_id="work-id",
    )

    # Assert the state management
    assert mocked_helper.get_state.call_count == 2
    mocked_helper.set_state.assert_called_once_with(
        state={"last_run": "2025-04-17T15:24:00+00:00"}
    )

    # Assert the STIX object processing
    mocked_helper.stix2_create_bundle.assert_called_once_with(
        items=[STIX_OBJECT, connector.converter.author, connector.converter.tlp_marking]
    )
    mocked_helper.send_stix2_bundle.assert_called_once_with(
        bundle="bundle", cleanup_inconsistent_bundle=True, work_id="work-id"
    )

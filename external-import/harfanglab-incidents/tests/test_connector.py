from datetime import datetime, timezone
from unittest.mock import Mock

from harfanglab_incidents_connector.connector import HarfanglabIncidentsConnector


def test_process_message_sends_bundle_with_update_flag() -> None:
    connector = HarfanglabIncidentsConnector.__new__(HarfanglabIncidentsConnector)
    connector.helper = Mock()
    connector.helper.connect_name = "harfanglab-incidents"
    connector.last_import_datetime_value = datetime.now(tz=timezone.utc)
    connector._initiate_work = Mock(return_value="work-id")
    connector.create_stix_bundle = Mock(return_value="bundle")
    connector._set_state_last_datetime = Mock()
    connector._terminate_work = Mock()

    connector.process_message()

    connector.helper.send_stix2_bundle.assert_called_once_with(
        "bundle",
        work_id="work-id",
        update=True,
        cleanup_inconsistent_bundle=True,
    )

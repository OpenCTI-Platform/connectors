from unittest.mock import MagicMock

from crowdstrike_feeds_connector.connector import CrowdStrike
from crowdstrike_feeds_services.utils import paginate


def test_process_message_marks_paginated_api_error_as_failed_work():
    connector = CrowdStrike.__new__(CrowdStrike)

    connector.helper = MagicMock()
    connector.helper.connect_name = "CrowdStrike"

    connector._current_unix_timestamp = MagicMock(return_value=1234567890)
    connector._load_state = MagicMock(return_value={})
    connector._initiate_work = MagicMock(return_value="work-1")

    importer = MagicMock()
    importer.name = "Actor"

    def start(work_id, state):
        @paginate
        def query(*args, limit=25, offset=0, **kwargs):
            return {
                "errors": [
                    {
                        "code": 401,
                        "message": "Unauthorized",
                    }
                ],
                "meta": {
                    "trace_id": "test-trace-id",
                },
                "resources": [],
            }

        list(query())
        return state

    importer.start.side_effect = start
    connector.importers = [importer]

    connector.process_message()

    connector.helper.api.work.to_processed.assert_called_once_with(
        "work-1",
        "Unauthorized (401)",
        in_error=True,
    )
    connector.helper.set_state.assert_not_called()

import unittest

import pytest

from .common_fixtures import setup_config, stream_event, api_response


@pytest.mark.usefixtures("stream_event", "setup_config")
class TestCrowdstrikeConnector(unittest.TestCase):

    def test_check_stream_id(self) -> None:
        """
        Test that a Value Error is raised
        When the stream ID is missing
        """
        self.mock_helper.connect_live_stream_id = None

        with pytest.raises(ValueError) as exc_info:
            self.connector.check_stream_id()

        result = str(exc_info.value)
        expected_result = "Missing stream ID, please check your configurations."

        self.assertEqual(result, expected_result)

    def test_stream_check_process_message(self) -> None:
        """
        Test that a Value Error is raised
        When the message from stream is not properly formatted
        """
        with pytest.raises(ValueError) as exc_info:
            self.connector._process_message(self.ioc_event_create)

        result = str(exc_info.value)
        expected_result = "Cannot process the message"

        self.assertEqual(result, expected_result)

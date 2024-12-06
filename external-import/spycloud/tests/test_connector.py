# import pytest


class TestSpyCloudConnector(object):
    def test_to_do(self) -> None:
        """
        Check if running test works
        """
        # Use the helper
        # self.mock_helper()
        value_received = "Value is True"
        expected_result = "Value is True"

        assert value_received == expected_result

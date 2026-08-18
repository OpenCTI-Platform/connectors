from unittest.mock import MagicMock

from ransomwarelive_client.api_v2 import RansomwareAPIV2Client


def test_v2_client_get_groups_uses_groups_endpoint():
    # Given
    client = RansomwareAPIV2Client(helper=MagicMock(), base_url="https://example/v2")
    client._send_request = MagicMock(return_value=[])

    # When
    client.get_groups()

    # Then
    client._send_request.assert_called_once_with("https://example/v2/groups")


def test_v2_client_get_recent_victims_uses_recentvictims_endpoint():
    # Given
    client = RansomwareAPIV2Client(helper=MagicMock(), base_url="https://example/v2")
    client._send_request = MagicMock(return_value=[])

    # When
    client.get_recent_victims()

    # Then
    client._send_request.assert_called_once_with("https://example/v2/recentvictims")


def test_v2_client_get_victims_uses_year_month_endpoint():
    # Given
    client = RansomwareAPIV2Client(helper=MagicMock(), base_url="https://example/v2")
    client._send_request = MagicMock(return_value=[])

    # When
    client.get_victims(2025, 7)

    # Then
    client._send_request.assert_called_once_with("https://example/v2/victims/2025/7")

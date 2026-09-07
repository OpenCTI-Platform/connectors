from unittest.mock import MagicMock

from ransomwarelive_client.api_pro import RansomwareAPIProClient


def test_pro_client_sets_x_api_key_header():
    # Given
    client = RansomwareAPIProClient(
        helper=MagicMock(),
        base_url="https://api-pro.ransomware.live",
        api_key="test-key",
    )

    # When
    headers = client.session_headers

    # Then
    assert headers["X-API-KEY"] == "test-key"


def test_pro_client_get_groups_uses_groups_endpoint():
    # Given
    client = RansomwareAPIProClient(
        helper=MagicMock(),
        base_url="https://api-pro.ransomware.live",
        api_key="test-key",
    )
    client._get = MagicMock(return_value={"groups": []})

    # When
    client.get_groups()

    # Then
    client._get.assert_called_once_with("/groups", params=None)


def test_pro_client_get_recent_victims_uses_recent_endpoint():
    # Given
    client = RansomwareAPIProClient(
        helper=MagicMock(),
        base_url="https://api-pro.ransomware.live",
        api_key="test-key",
    )
    client._get = MagicMock(return_value={"victims": []})

    # When
    client.get_recent_victims()

    # Then
    client._get.assert_called_once_with("/victims/recent", params=None)


def test_pro_client_get_victims_uses_victims_endpoint_with_year_and_month():
    # Given
    client = RansomwareAPIProClient(
        helper=MagicMock(),
        base_url="https://api-pro.ransomware.live",
        api_key="test-key",
    )
    client._get = MagicMock(return_value={"victims": []})

    # When
    year = 2023
    month = 5
    client.get_victims(year, month)

    # Then
    client._get.assert_called_once_with(
        "/victims", params={"year": year, "month": month}
    )

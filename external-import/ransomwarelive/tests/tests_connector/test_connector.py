from unittest.mock import MagicMock

from ransomwarelive.ransom_conn import RansomwareAPIConnector
from ransomwarelive_client.api_pro import RansomwareAPIProClient
from ransomwarelive_client.api_v2 import RansomwareAPIV2Client


def test_build_api_client_should_return_v2_client():
    # Given
    connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
    connector.helper = MagicMock()
    connector.config = MagicMock()
    connector.config.ransomwarelive.api_base_url = "https://api.ransomware.live/v2"
    connector.config.ransomwarelive.api_key = None

    # When
    client = connector._build_api_client()

    # Then
    assert isinstance(client, RansomwareAPIV2Client)


def test_build_api_client_should_return_pro_client():
    # Given
    connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
    connector.helper = MagicMock()
    connector.config = MagicMock()
    connector.config.ransomwarelive.api_base_url = "https://api-pro.ransomware.live"
    connector.config.ransomwarelive.api_key = MagicMock()
    connector.config.ransomwarelive.api_key.get_secret_value.return_value = "pro-key"

    # When
    client = connector._build_api_client()

    # Then
    assert isinstance(client, RansomwareAPIProClient)

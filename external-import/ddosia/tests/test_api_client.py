import pytest
from unittest.mock import MagicMock, patch
from ddosia_client.api_client import DdosiaClient
from pycti import OpenCTIConnectorHelper

class TestDdosiaClient:
    @pytest.fixture
    def mock_helper(self):
        return MagicMock(spec=OpenCTIConnectorHelper)

    @pytest.fixture
    def client(self, mock_helper):
        # Using a dummy URL for the client
        return DdosiaClient(helper=mock_helper, base_url="http://api.witha.name")

    def test_get_configs_pagination(self, client, mock_helper):
        """Test that get_configs correctly passes the page parameter."""
        with patch.object(client.session, 'get') as mock_get:
            mock_get.return_value.json.return_value = {"items": [], "total": 0}
            mock_get.return_value.status_code = 200
            
            client.get_configs(page=2)
            
            # Verify that the request was made with the correct page parameter
            args, kwargs = mock_get.call_args
            assert "page=2" in args[0] or kwargs.get("params", {}).get("page") == 2

    def test_get_config_success(self, client, mock_helper):
        """Test that get_config retrieves a specific configuration."""
        with patch.object(client.session, 'get') as mock_get:
            mock_get.return_value.json.return_value = {"targets": []}
            mock_get.return_value.status_code = 200
            
            result = client.get_config("cfg_123")
            
            assert result == {"targets": []}
            # Check if the correct URL was called
            args, _ = mock_get.call_args
            assert "cfg_123" in args[0]

    def test_request_json_error(self, client, mock_helper):
        """Test that _request_json raises an exception on HTTP error."""
        with patch.object(client.session, 'get') as mock_get:
            mock_get.return_value.raise_for_status.side_effect = Exception("HTTP Error")
            
            with pytest.raises(Exception):
                client.get_configs()

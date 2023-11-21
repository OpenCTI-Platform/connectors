import pytest
from unittest.mock import patch, Mock
from hostio.ipinfo import IPInfo  # Updated import statement
from hostio.tests.constants import load_fixture, generate_random_token  # Updated import statement


class TestIPInfo:
    valid_token = generate_random_token()
    invalid_token = "invalid_token"
    valid_ip = "8.8.8.8"  # Example of a valid IP
    invalid_ip = "invalid_ip"
    fixture = 'ipinfo_{}.json'
    license_list = ['free', 'base', 'standard', 'business']
    free_keys = ['ip', 'hostname', 'anycast', 'city', 'region', 'country', 'loc', 'org', 'postal', 'timezone']
    base_keys = ['ip', 'hostname', 'anycast', 'city', 'region', 'country', 'loc', 'org', 'postal', 'timezone', 'asn']
    standard_keys = ['ip', 'hostname', 'anycast', 'city', 'region', 'country', 'loc', 'org', 'postal', 'timezone', 'asn', 'company', 'privacy']
    business_keys = ['ip', 'hostname', 'anycast', 'city', 'region', 'country', 'loc', 'postal', 'timezone', 'asn', 'company', 'privacy', 'abuse', 'domains']


    @patch('hostio.ipinfo.getHandler')
    def test_init_valid_token_and_ip(self, mock_get_handler):
        """Test initialization with valid token and IP."""
        mock_handler = Mock()
        
        for license in self.license_list:
            mock_handler.getDetails.return_value.all = load_fixture(self.fixture.format(license))
            mock_get_handler.return_value = mock_handler
            ip_info = IPInfo(self.valid_token, self.valid_ip)
            assert ip_info.ip == self.valid_ip
            assert ip_info.get_details() == load_fixture(self.fixture.format(license))
            for key in eval(f'self.{license}_keys'):
                assert key in ip_info.get_details().keys()
            mock_get_handler.assert_called_once_with(token=self.valid_token)
            mock_handler.getDetails.assert_called_once_with(self.valid_ip)
            mock_handler.reset_mock()
            mock_get_handler.reset_mock()


    def test_init_invalid_token(self):
        """Test initialization with invalid token."""
        with pytest.raises(ValueError) as exc_info:
            IPInfo(self.invalid_token, self.valid_ip)
        
        assert "Invalid API token provided." in str(exc_info.value)

    def test_init_invalid_ip(self):
        """Test initialization with invalid IP."""
        with pytest.raises(ValueError) as exc_info:
            IPInfo(self.valid_token, self.invalid_ip)
        
        assert f"Invalid IP address: {self.invalid_ip}" in str(exc_info.value)

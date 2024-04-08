import pytest

from .common_fixtures import api_response, setup_config, stream_event  # noqa: F401


@pytest.mark.usefixtures("stream_event", "setup_config", "api_response")
class TestCrowdstrikeConnector(object):

    domain_pattern = "[domain-name:value = 'siestakeying.com']"
    ipv4_pattern = "[ipv4-addr:value = '188.143.233.116']"
    ipv6_pattern = "[ipv6-addr:value = '2a02:2f01:7504:5000:0:0:7429:4782']"
    sha256_pattern = "[file:hashes.'SHA-256' = '37c09c95f77e5677332de338b7e972cff67347ed2c807c15b415c41b0d4a9ac4']"
    md5_pattern = "[file:hashes.'MD5' = '7a465344a58a6c67d5a733a815ef4cb7']"

    def test_parse_indicator_pattern(self) -> None:
        """
        Check if indicator pattern from OpenCTI is properly parsed
        """
        pattern_parsed = self.mock_client._parse_indicator_pattern(self.domain_pattern)
        expected_result = "domain-name:value"

        assert pattern_parsed == expected_result

    @pytest.mark.parametrize(
        "pattern, expected_result",
        [
            (domain_pattern, "domain"),
            (ipv4_pattern, "ipv4"),
            (ipv6_pattern, "ipv6"),
            (sha256_pattern, "sha256"),
            (md5_pattern, "md5"),
        ],
    )
    def test_correct_ioc_type_mapping(self, pattern, expected_result) -> None:
        """
        Check if indicator types from OpenCTI map properly with Crowdstrike types
        """
        obs_type = self.mock_client._map_indicator_type(pattern)

        assert obs_type == expected_result

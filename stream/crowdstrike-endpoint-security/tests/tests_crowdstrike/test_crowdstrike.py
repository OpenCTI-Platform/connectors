import pytest

from .common_fixtures import (  # noqa: F401 # pylint:disable=unused-import
    api_response,
    setup_config,
    stream_event,
)


@pytest.mark.usefixtures("stream_event", "setup_config", "api_response")
class TestCrowdstrikeConnector(object):

    domain_pattern = "[domain-name:value = 'siestakeying.com']"
    ipv4_pattern = "[ipv4-addr:value = '188.143.233.116']"
    ipv6_pattern = "[ipv6-addr:value = '2a02:2f01:7504:5000:0:0:7429:4782']"
    sha256_pattern = "[file:hashes.'SHA-256' = '37c09c95f77e5677332de338b7e972cff67347ed2c807c15b415c41b0d4a9ac4']"
    md5_pattern = "[file:hashes.'MD5' = '7a465344a58a6c67d5a733a815ef4cb7']"
    bad_pattern = "[url:value = 'https://t.me/karl3on']"

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
    def test_correct_ioc_type_mapping(self, pattern: str, expected_result: str) -> None:
        """
        Check if indicator types from OpenCTI map properly with Crowdstrike types
        :param pattern: Pattern in string
        :param expected_result: Result in string
        :return: None
        """
        obs_type = self.mock_client._map_indicator_type(pattern)

        assert obs_type == expected_result

    def test_incorrect_ioc_type_mapping(self) -> None:
        """
        Check if indicator types from OpenCTI mapper return "None"
        if pattern not found
        """
        obs_type = self.mock_client._map_indicator_type(self.bad_pattern)

        assert obs_type is None

    @pytest.mark.parametrize(
        "score, expected_result",
        [
            (10, "informational"),
            (30, "low"),
            (50, "medium"),
            (70, "high"),
            (90, "critical"),
        ],
    )
    def test_correct_severity_mapping(self, score: int, expected_result: str) -> None:
        """
        Check if severity in Crowdstrike is properly mapped with integer scoring from OpenCTI
        :param score: Score in int
        :param expected_result: Result in str
        :return: None
        """
        self.mock_helper.get_attribute_in_extension.return_value = score

        indicator_severity = self.mock_client._map_severity(self.ioc_data)

        assert indicator_severity == expected_result

    def test_incorrect_severity_mapping(self) -> None:
        """
        Check if indicator score from OpenCTI mapper return "None"
        if score is not found
        :return: None
        """
        self.mock_helper.get_attribute_in_extension.return_value = None

        indicator_severity = self.mock_client._map_severity(self.ioc_data)

        assert indicator_severity is None

    @pytest.mark.parametrize(
        "ioc_type, config_attr, config_value, expected_action",
        [
            ("ipv4", "action_on_ip", "detect", "detect"),
            ("ipv4", "action_on_ip", "no_action", "no_action"),
            ("ipv6", "action_on_ip", "detect", "detect"),
            ("domain", "action_on_domain", "detect", "detect"),
            ("domain", "action_on_domain", "no_action", "no_action"),
            ("sha256", "action_on_hash", "detect", "detect"),
            ("sha256", "action_on_hash", "prevent", "prevent"),
            ("sha256", "action_on_hash", "allow", "allow"),
            ("sha256", "action_on_hash", "no_action", "no_action"),
            ("md5", "action_on_hash", "prevent", "prevent"),
            ("unknown_type", "action_on_ip", "no_action", "detect"),
        ],
    )
    def test_resolve_action(
        self, ioc_type: str, config_attr: str, config_value: str, expected_action: str
    ) -> None:
        """
        Check that _resolve_action returns the correct action based on config
        """
        setattr(self.mock_config, config_attr, config_value)
        action = self.mock_client._resolve_action(ioc_type)
        assert action == expected_action

    def test_generate_indicator_body_uses_configured_action(self) -> None:
        """
        Check that _generate_indicator_body sets the action from config
        """
        self.mock_config.action_on_hash = "prevent"
        self.mock_helper.get_attribute_in_extension.return_value = 50
        self.mock_helper.get_attribute_in_mitre_extension.return_value = None

        data = {
            "pattern": "[file:hashes.'SHA-256' = 'abc123']",
            "labels": ["test"],
        }
        body = self.mock_client._generate_indicator_body(data, "abc123")

        assert body is not None
        indicator = body["indicators"][0]
        assert indicator["action"] == "prevent"
        assert indicator["mobile_action"] == "prevent"

    def test_generate_indicator_body_default_detect_for_ip(self) -> None:
        """
        Check that _generate_indicator_body defaults to detect for IP
        """
        self.mock_config.action_on_ip = "detect"
        self.mock_helper.get_attribute_in_extension.return_value = 70
        self.mock_helper.get_attribute_in_mitre_extension.return_value = None

        data = {
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
        }
        body = self.mock_client._generate_indicator_body(data, "1.2.3.4")

        assert body is not None
        indicator = body["indicators"][0]
        assert indicator["action"] == "detect"
        assert indicator["mobile_action"] == "detect"

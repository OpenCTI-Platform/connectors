"""Unit tests for ConnectorSettings."""

import pytest
from lab539_aitm_connector.settings import AiTMFeedConfig
from pydantic import SecretStr, ValidationError


class TestAiTMFeedConfig:
    """Tests for AiTMFeedConfig validation."""

    def test_api_key_required(self):
        """AiTMFeedConfig should fail without an api_key."""
        with pytest.raises(ValidationError):
            AiTMFeedConfig()

    def test_api_key_accepted(self):
        """AiTMFeedConfig should accept a valid api_key."""
        cfg = AiTMFeedConfig(api_key=SecretStr("test-key"))
        assert cfg.api_key.get_secret_value() == "test-key"

    def test_defaults(self):
        """AiTMFeedConfig should apply correct defaults."""
        cfg = AiTMFeedConfig(api_key=SecretStr("test-key"))
        assert cfg.api_base_url == "https://aitm.lab539.io/v1.0"
        assert cfg.tlp_level == "amber"
        assert cfg.first_run_lookback_days == 7

    def test_invalid_tlp_level(self):
        """AiTMFeedConfig should reject invalid TLP levels."""
        with pytest.raises(ValidationError):
            AiTMFeedConfig(api_key=SecretStr("test-key"), tlp_level="invalid")

    def test_valid_tlp_levels(self):
        """AiTMFeedConfig should accept all valid TLP levels."""
        for level in ["white", "green", "amber", "amber+strict", "red"]:
            cfg = AiTMFeedConfig(api_key=SecretStr("test-key"), tlp_level=level)
            assert cfg.tlp_level == level

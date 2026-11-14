from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConnectorSettings, ConfigValidationError


def _settings(mirage: dict[str, Any]) -> ConnectorSettings:
    class FakeSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {"id": "connector-id"},
                    "offseq_mirage": mirage,
                }
            )

    return FakeSettings()


def test_defaults_need_no_mirage_section():
    settings = _settings({})
    assert isinstance(settings, BaseConnectorSettings)
    assert (
        str(settings.offseq_mirage.feed_url)
        == "https://feeds.offseq.com/mirage-feed/latest/stix/mirage.json"
    )
    assert settings.offseq_mirage.tlp_level == "clear"
    assert settings.connector.name == "OffSeq Mirage"


@pytest.mark.parametrize(
    "mirage",
    [{"feed_url": "not a url"}, {"tlp_level": "purple"}, {"batch_size": 10}],
)
def test_invalid_values_fail_at_startup(mirage):
    with pytest.raises(ConfigValidationError):
        _settings(mirage)

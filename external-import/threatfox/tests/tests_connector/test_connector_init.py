from unittest.mock import MagicMock, patch

import pytest
from src.__main__ import ThreatFox


@pytest.mark.parametrize("legacy", [True, False], ids=["legacy_url", "current_url"])
def test_legacy_csv_url_is_reported_at_startup(legacy):
    config = MagicMock()
    config.threatfox.has_legacy_csv_url = legacy
    config.threatfox.ioc_to_import = "all_types"
    config.threatfox.use_commercial = False

    with (
        patch("src.__main__.ConfigLoader", return_value=config),
        patch("src.__main__.OpenCTIConnectorHelper") as helper_cls,
    ):
        ThreatFox()

    warnings = helper_cls.return_value.connector_logger.warning.call_args_list
    assert any("retired public export" in call.args[0] for call in warnings) is legacy


@pytest.mark.parametrize("community", [True, False], ids=["with_key", "without_key"])
def test_commercial_mode_builds_the_spamhaus_client(community):
    config = MagicMock()
    config.threatfox.has_legacy_csv_url = False
    config.threatfox.ioc_to_import = "all_types"
    config.threatfox.use_commercial = True
    config.threatfox.community_configured = community

    with (
        patch("src.__main__.ConfigLoader", return_value=config),
        patch("src.__main__.OpenCTIConnectorHelper"),
        patch("src.__main__.SpamhausClient") as client_cls,
    ):
        connector = ThreatFox()

    assert connector.spamhaus_client is client_cls.return_value
    assert connector.community_fallback is community
    kwargs = client_cls.call_args.kwargs
    assert kwargs["connector_name"] == "threatfox"
    assert kwargs["username"] is config.threatfox.spamhaus_username
    assert kwargs["password"] is config.threatfox.spamhaus_password


def test_community_mode_has_no_spamhaus_client():
    config = MagicMock()
    config.threatfox.has_legacy_csv_url = False
    config.threatfox.ioc_to_import = "all_types"
    config.threatfox.use_commercial = False

    with (
        patch("src.__main__.ConfigLoader", return_value=config),
        patch("src.__main__.OpenCTIConnectorHelper"),
        patch("src.__main__.SpamhausClient") as client_cls,
    ):
        connector = ThreatFox()

    assert connector.spamhaus_client is None
    client_cls.assert_not_called()

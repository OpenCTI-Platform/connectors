from unittest.mock import MagicMock, patch

import pytest
from src.__main__ import ThreatFox


@pytest.mark.parametrize("legacy", [True, False], ids=["legacy_url", "current_url"])
def test_legacy_csv_url_is_reported_at_startup(legacy):
    config = MagicMock()
    config.threatfox.has_legacy_csv_url = legacy
    config.threatfox.ioc_to_import = "all_types"

    with (
        patch("src.__main__.ConfigLoader", return_value=config),
        patch("src.__main__.OpenCTIConnectorHelper") as helper_cls,
    ):
        ThreatFox()

    warnings = helper_cls.return_value.connector_logger.warning.call_args_list
    assert any("retired public export" in call.args[0] for call in warnings) is legacy

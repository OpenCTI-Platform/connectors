from unittest.mock import MagicMock, patch

from main import BaseRFConnector
from rflib.constants import RISK_LIST_TYPE_MAPPER


def _build_base_connector(rf_config_values):
    config = MagicMock()
    for name, value in rf_config_values.items():
        setattr(config.recorded_future, name, value)
    with patch("main.ConfigLoader", return_value=config), patch(
        "main.OpenCTIConnectorHelper"
    ), patch("main.RFClient"), patch("main.RecordedFutureApiClient"):
        return BaseRFConnector()


# Scenario: each risk list gets the threshold of its own setting
def test_risk_list_thresholds_are_keyed_like_the_risk_lists():
    connector = _build_base_connector(
        {
            "risk_list_threshold": 70,
            "risk_list_threshold_ip": 80,
            "risk_list_threshold_domain": 75,
            "risk_list_threshold_url": 65,
            "risk_list_threshold_hash": 90,
            "risk_list_threshold_vulnerability": 0,
        }
    )

    assert set(connector.risk_list_thresholds) == set(RISK_LIST_TYPE_MAPPER)
    assert connector.risk_list_threshold == 70
    assert connector.risk_list_thresholds == {
        "IpAddress": 80,
        "InternetDomainName": 75,
        "URL": 65,
        "Hash": 90,
        "Vuln": 0,
    }

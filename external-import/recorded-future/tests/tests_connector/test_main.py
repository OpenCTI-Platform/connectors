from unittest.mock import MagicMock, patch

from main import BaseRFConnector
from rflib.constants import RISK_LIST_TYPE_MAPPER, RiskListType


def _build_base_connector(rf_config_values):
    config = MagicMock()
    for name, value in rf_config_values.items():
        setattr(config.recorded_future, name, value)
    with patch("main.ConfigLoader", return_value=config), patch(
        "main.OpenCTIConnectorHelper"
    ), patch("main.RFClient"), patch("main.RecordedFutureApiClient"):
        return BaseRFConnector()


# Scenario: every risk list has a threshold entry and an entry in the mapper
def test_every_risk_list_type_has_a_threshold_and_a_mapper_entry():
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

    assert set(connector.risk_list_thresholds) == set(RiskListType)
    assert set(RISK_LIST_TYPE_MAPPER) == set(RiskListType)
    assert connector.risk_list_threshold == 70
    assert connector.risk_list_thresholds == {
        RiskListType.IP: 80,
        RiskListType.DOMAIN: 75,
        RiskListType.URL: 65,
        RiskListType.HASH: 90,
        RiskListType.VULN: 0,
    }


# Scenario: the enum values stay the strings used in work names and STIX classes
def test_risk_list_types_format_as_their_former_string_keys():
    assert [f"{risk_list_type}" for risk_list_type in RiskListType] == [
        "IpAddress",
        "InternetDomainName",
        "URL",
        "Hash",
        "Vuln",
    ]

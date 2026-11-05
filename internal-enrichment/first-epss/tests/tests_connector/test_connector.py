from unittest.mock import MagicMock

import pytest
from connectors_sdk import ApiServerError
from connectors_sdk.exceptions.error import DataRetrievalError
from internal_enrichment_connector import FirstEPSSConnector

VULNERABILITY = {
    "id": "vulnerability--4e4a8fb1-9d5c-5b4d-8d40-1d3c7a1d3b9e",
    "type": "vulnerability",
    "name": "CVE-2021-44228",
}


@pytest.fixture
def helper() -> MagicMock:
    helper = MagicMock()
    helper.connect_scope = "vulnerability"
    helper.check_max_tlp.return_value = True
    helper.send_stix2_bundle.return_value = ["bundle"]
    return helper


@pytest.fixture
def connector(helper: MagicMock) -> FirstEPSSConnector:
    config = MagicMock()
    config.first_epss.api_base_url = "https://api.first.org/data/v1/epss"
    connector = FirstEPSSConnector(config=config, helper=helper)
    connector.api = MagicMock()
    return connector


@pytest.fixture
def message() -> dict:
    return {
        "stix_objects": [VULNERABILITY],
        "stix_entity": VULNERABILITY,
        "enrichment_entity": {"objectMarking": []},
    }


def test_process_message_should_send_epss_scores_when_cve_is_known(
    connector, helper, message
):
    connector.api.get_epss_scores.return_value = [
        {"cve": "CVE-2021-44228", "epss": "0.99999", "percentile": "1.0"}
    ]

    connector.process_message(message)

    # The incoming entity, then the enriched vulnerability and its author
    _, vulnerability, author = helper.stix2_create_bundle.call_args.args[0]
    assert vulnerability["name"] == "CVE-2021-44228"
    assert vulnerability["x_opencti_epss_score"] == 0.99999
    assert vulnerability["x_opencti_epss_percentile"] == 1.0
    assert author["name"] == "FIRST EPSS"
    helper.send_stix2_bundle.assert_called_once()


def test_process_message_should_send_nothing_when_cve_is_unknown(
    connector, helper, message
):
    connector.api.get_epss_scores.return_value = []

    result = connector.process_message(message)

    assert result == "[CONNECTOR] No information found"
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_should_raise_when_api_fails(connector, helper, message):
    connector.api.get_epss_scores.side_effect = ApiServerError(
        "Server error (502) on GET https://api.first.org/data/v1/epss",
        status_code=502,
    )

    with pytest.raises(DataRetrievalError, match="CVE-2021-44228"):
        connector.process_message(message)

    helper.send_stix2_bundle.assert_not_called()

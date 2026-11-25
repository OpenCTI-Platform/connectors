import pytest
from src.connector.sekoia import SekoiaConnector


def _indicator(**fields) -> dict:
    """Build a Sekoia.io indicator as the collection API returns it."""
    return {
        "type": "indicator",
        "id": "indicator--ae12b415-4e4a-482a-8a02-e3e7b32d5b17",
        "pattern": "[domain-name:value = 'example.com']",
        "x_ic_observable_types": ["domain-name"],
        "confidence": 70,
        "modified": "2026-11-19T17:01:46.974649Z",
        "valid_until": "2027-02-14T00:00:00Z",
        **fields,
    }


@pytest.mark.parametrize("confidence_score", [None, 80])
def test_revoked_indicator_gets_score_zero_and_revocation_date(confidence_score):
    item = _indicator(revoked=True)

    SekoiaConnector._add_main_observable_type_to_indicators([item], confidence_score)

    assert item["x_opencti_score"] == 0
    assert item["valid_until"] == item["modified"]


def test_active_indicator_score_is_the_confidence():
    item = _indicator(revoked=False)

    SekoiaConnector._add_main_observable_type_to_indicators([item], None)

    assert item["x_opencti_score"] == 70
    assert item["valid_until"] == "2027-02-14T00:00:00Z"


def test_active_indicator_score_is_the_configured_score():
    item = _indicator()

    SekoiaConnector._add_main_observable_type_to_indicators([item], 80)

    assert item["x_opencti_score"] == 80
    assert item["valid_until"] == "2027-02-14T00:00:00Z"

from connector.confidence import (
    analyst_confidence_wins,
    confidence_value,
    make_sync_record,
)


def test_confidence_value_defaults_missing_to_zero():
    assert confidence_value({}) == 0
    assert confidence_value({"confidence": "42"}) == 42


def test_analyst_confidence_wins_when_opencti_is_higher():
    assert analyst_confidence_wins(
        {"confidence": 80},
        api_item={"confidence": 50},
    )


def test_analyst_confidence_does_not_win_when_upstream_is_higher_or_equal():
    assert not analyst_confidence_wins(
        {"confidence": 40},
        api_item={"confidence": 60},
    )
    assert not analyst_confidence_wins(
        {"confidence": 60},
        api_item={"confidence": 60},
    )


def test_make_sync_record_stores_upstream_confidence():
    assert make_sync_record({"confidence": 55}) == {"upstream_confidence": 55}

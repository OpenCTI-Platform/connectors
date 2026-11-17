"""Tests for the CrowdStrike indicator extractor."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from conftest import (
    FakeIndicatorsAPI,
    ScriptedClient,
    build_extractor,
    load_fixture,
    make_indicator,
    ok,
)
from crowdstrike_indicators.errors import CrowdStrikeAPIError, IndicatorValidationError
from crowdstrike_indicators.extractor import (
    NO_ERROR_MESSAGE,
    first_marker_cursor,
    marker_datetime,
)
from crowdstrike_indicators.models import CrowdStrikeIndicator

BASE = 1_700_000_000
FROM_BASE = datetime.fromtimestamp(BASE, tz=UTC)


def _ids(result) -> list[str]:
    return [indicator.id for _, indicator in result]


# --- Datetime and boundary -------------------------------------------------


def test_marker_prefix_gives_the_datetime():
    assert marker_datetime("1700000005abc0001") == datetime(
        2023, 11, 14, 22, 13, 25, tzinfo=UTC
    )


def test_first_filter_includes_a_whole_second_from_date():
    api = FakeIndicatorsAPI([])
    build_extractor(api).extract(datetime.fromtimestamp(1_700_000_005, tz=UTC), 10)
    assert api.calls[0]["filter"] == "_marker:>='1700000005'"


def test_first_filter_rounds_a_fractional_from_date_up():
    api = FakeIndicatorsAPI([])
    from_date = datetime.fromtimestamp(1_700_000_005, tz=UTC) + timedelta(
        milliseconds=700
    )
    build_extractor(api).extract(from_date, 10)
    assert api.calls[0]["filter"] == "_marker:>='1700000006'"


def test_first_marker_cursor_uses_utc_whatever_the_timezone():
    # 23:13:25 at UTC+1 is 22:13:25 UTC, which is Unix second 1700000005.
    plus_one = datetime(2023, 11, 14, 23, 13, 25, tzinfo=timezone(timedelta(hours=1)))
    assert first_marker_cursor(plus_one) == "1700000005"


@pytest.mark.parametrize(
    ("from_date", "cursor"),
    [
        (datetime(2000, 1, 1, tzinfo=UTC), "0946684800"),
        (datetime(2001, 9, 9, 1, 46, 39, tzinfo=UTC), "0999999999"),
        (datetime(2001, 9, 9, 1, 46, 40, tzinfo=UTC), "1000000000"),
        (datetime(2000, 1, 1, 0, 0, 0, 500_000, tzinfo=UTC), "0946684801"),
        (datetime(1969, 12, 31, tzinfo=UTC), "0000000000"),
        (datetime(1970, 1, 1, tzinfo=UTC), "0000000000"),
        (datetime(2023, 11, 14, 22, 13, 25, tzinfo=UTC), "1700000005"),
    ],
)
def test_first_marker_cursor_always_has_ten_digits(from_date, cursor):
    assert first_marker_cursor(from_date) == cursor


@pytest.mark.parametrize(
    "from_date",
    [datetime(2000, 1, 1, tzinfo=UTC), datetime(1969, 12, 31, tzinfo=UTC)],
    ids=["from-2000", "before-1970"],
)
def test_early_from_date_returns_every_later_indicator(from_date):
    rows = load_fixture("indicators_sample.json")["resources"]
    api = FakeIndicatorsAPI(rows)

    result = build_extractor(api).extract(from_date, 100)

    assert len(result) == len(rows)
    assert api.calls[0]["filter"] == f"_marker:>='{first_marker_cursor(from_date)}'"


def test_same_second_as_from_date_is_included():
    api = FakeIndicatorsAPI(
        [
            make_indicator(1, second=1_700_000_004),
            make_indicator(2, second=1_700_000_005),
            make_indicator(3, second=1_700_000_006),
        ]
    )
    result = build_extractor(api).extract(
        datetime.fromtimestamp(1_700_000_005, tz=UTC), 10
    )
    assert _ids(result) == ["ioc-2", "ioc-3"]
    assert result[0][0] == datetime.fromtimestamp(1_700_000_005, tz=UTC)


def test_earlier_second_is_excluded_for_a_fractional_from_date():
    api = FakeIndicatorsAPI(
        [
            make_indicator(1, second=1_700_000_005),
            make_indicator(2, second=1_700_000_006),
        ]
    )
    from_date = datetime.fromtimestamp(1_700_000_005, tz=UTC) + timedelta(
        milliseconds=700
    )
    result = build_extractor(api).extract(from_date, 10)
    assert _ids(result) == ["ioc-2"]
    assert all(dt >= from_date for dt, _ in result)


# --- Pagination --------------------------------------------------------------


def test_results_span_several_pages_in_ascending_order():
    api = FakeIndicatorsAPI([make_indicator(i) for i in range(2500)])
    result = build_extractor(api).extract(FROM_BASE, 2500)

    assert _ids(result) == [f"ioc-{i}" for i in range(2500)]
    datetimes = [dt for dt, _ in result]
    assert datetimes == sorted(datetimes)
    assert all(isinstance(indicator, CrowdStrikeIndicator) for _, indicator in result)
    assert all(call["limit"] == 1000 for call in api.calls)


def test_result_is_cut_to_the_cap_after_two_full_pages():
    api = FakeIndicatorsAPI([make_indicator(i) for i in range(2500)])
    result = build_extractor(api).extract(FROM_BASE, 1200)

    assert len(api.calls) == 2
    assert [call["limit"] for call in api.calls] == [1000, 1000]
    assert _ids(result) == [f"ioc-{i}" for i in range(1200)]


def test_cap_is_reached_exactly_despite_repeated_boundary_rows():
    # The case that a "request only what is missing" loop gets wrong.
    api = FakeIndicatorsAPI([make_indicator(i) for i in range(1300)])
    result = build_extractor(api).extract(FROM_BASE, 1200)
    assert len(result) == 1200


def test_continuation_pages_start_at_the_last_collected_marker():
    api = FakeIndicatorsAPI([make_indicator(i) for i in range(1500)])
    build_extractor(api).extract(FROM_BASE, 1500)
    last_of_first_page = make_indicator(999)["_marker"]
    assert api.calls[1]["filter"] == f"_marker:>='{last_of_first_page}'"


def test_overlapping_boundary_row_is_not_duplicated():
    api = FakeIndicatorsAPI([make_indicator(i) for i in range(5)])
    result = build_extractor(api, page_size=2).extract(FROM_BASE, 10)

    ids = _ids(result)
    assert ids == [f"ioc-{i}" for i in range(5)]
    assert len(ids) == len(set(ids))


def test_page_without_new_rows_stops_pagination():
    page = ok({"resources": [make_indicator(1), make_indicator(2)]})
    client = ScriptedClient([page, page, page])
    result = build_extractor(client).extract(FROM_BASE, 10)

    assert _ids(result) == ["ioc-1", "ioc-2"]
    assert len(client.calls) == 2


def test_empty_first_page_returns_an_empty_list():
    client = ScriptedClient([ok({"resources": []})])
    assert build_extractor(client).extract(FROM_BASE, 10) == []
    assert len(client.calls) == 1


@pytest.mark.parametrize("body", [{}, {"resources": None}])
def test_missing_resources_is_an_empty_page(body):
    client = ScriptedClient([ok(body)])
    assert build_extractor(client).extract(FROM_BASE, 10) == []


def test_realistic_page_fixture(indicators_page):
    client = ScriptedClient([ok(indicators_page)])
    result = build_extractor(client).extract(FROM_BASE, 10)

    assert _ids(result) == [raw["id"] for raw in indicators_page["resources"]]
    first = result[0][1]
    assert first.model_extra is not None
    assert first.model_extra["reports"] == ["CSIT-00001"]
    assert first.labels is not None and first.labels[0].name == (
        "MaliciousConfidence/High"
    )


def test_invalid_arguments_do_not_reach_the_api():
    client = ScriptedClient([])
    extractor = build_extractor(client)
    with pytest.raises(ValueError):
        extractor.extract(FROM_BASE, 0)
    with pytest.raises(ValueError):
        extractor.extract(datetime(2026, 1, 1), 10)
    assert client.calls == []


# --- Validation errors -------------------------------------------------------


def test_validation_failure_stops_the_extraction_with_the_raw_payload():
    bad = make_indicator(2, last_updated="not a timestamp")
    client = ScriptedClient([ok({"resources": [make_indicator(1), bad]})])

    with pytest.raises(IndicatorValidationError) as caught:
        build_extractor(client).extract(FROM_BASE, 10)

    error = caught.value
    assert error.indicator_id == "ioc-2"
    assert error.raw == bad
    assert [tuple(e["loc"]) for e in error.errors] == [("last_updated",)]
    assert "ioc-2" in str(error) and "last_updated" in str(error)


def test_validation_failure_without_id():
    bad = {"indicator": "x", "type": "domain"}
    client = ScriptedClient([ok({"resources": [bad]})])

    with pytest.raises(IndicatorValidationError) as caught:
        build_extractor(client).extract(FROM_BASE, 10)

    assert caught.value.indicator_id is None
    assert caught.value.raw == bad
    assert "<no id>" in str(caught.value)


def test_non_dict_resource_fails_validation():
    client = ScriptedClient([ok({"resources": ["oops"]})])
    with pytest.raises(IndicatorValidationError) as caught:
        build_extractor(client).extract(FROM_BASE, 10)
    assert caught.value.raw == "oops"


# --- API errors --------------------------------------------------------------


def test_permission_denied_raises_with_the_first_error_message(error_403):
    client = ScriptedClient([{"status_code": 403, "headers": {}, "body": error_403}])

    with pytest.raises(CrowdStrikeAPIError) as caught:
        build_extractor(client).extract(FROM_BASE, 10)

    assert caught.value.status_code == 403
    assert caught.value.message == "access denied, authorization failed"
    assert "403" in str(caught.value)


@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"errors": None},
        {"errors": []},
        {"errors": {"message": "not a list"}},
        {"errors": ["not a dict"]},
        {"errors": [{"code": 500}]},
    ],
)
def test_server_error_without_message_uses_the_placeholder(body):
    response = {"status_code": 500, "headers": {}}
    if body is not None:
        response["body"] = body
    client = ScriptedClient([response])

    with pytest.raises(CrowdStrikeAPIError) as caught:
        build_extractor(client).extract(FROM_BASE, 10)

    assert caught.value.status_code == 500
    assert caught.value.message == NO_ERROR_MESSAGE


def test_missing_status_code_is_an_error():
    client = ScriptedClient([{"body": {"resources": [make_indicator(1)]}}])
    with pytest.raises(CrowdStrikeAPIError) as caught:
        build_extractor(client).extract(FROM_BASE, 10)
    assert caught.value.status_code == 0


def test_error_on_a_later_page_stops_the_extraction():
    client = ScriptedClient(
        [
            ok({"resources": [make_indicator(1)]}),
            {"status_code": 429, "body": {"errors": [{"message": "slow down"}]}},
        ]
    )
    with pytest.raises(CrowdStrikeAPIError) as caught:
        build_extractor(client).extract(FROM_BASE, 10)
    assert (caught.value.status_code, caught.value.message) == (429, "slow down")


# --- Raw page observation ----------------------------------------------------


def test_raw_pages_are_observed_before_a_validation_failure():
    page_1 = {"resources": [make_indicator(1)]}
    page_2 = {"resources": [make_indicator(1), make_indicator(2, _marker="bad")]}
    seen: list[dict] = []
    client = ScriptedClient([ok(page_1), ok(page_2)])

    with pytest.raises(IndicatorValidationError):
        build_extractor(client, on_raw_page=seen.append).extract(FROM_BASE, 10)

    assert seen == [page_1, page_2]


def test_every_page_is_observed_including_the_final_empty_one():
    seen: list[dict] = []
    api = FakeIndicatorsAPI([make_indicator(i) for i in range(3)])
    build_extractor(api, on_raw_page=seen.append, page_size=2).extract(FROM_BASE, 10)
    # Page 1: ioc-0, ioc-1. Page 2: ioc-1 (repeat), ioc-2. Page 3: ioc-2 only.
    assert [[raw["id"] for raw in page["resources"]] for page in seen] == [
        ["ioc-0", "ioc-1"],
        ["ioc-1", "ioc-2"],
        ["ioc-2"],
    ]

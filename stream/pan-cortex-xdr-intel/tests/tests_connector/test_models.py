from datetime import datetime, timezone

import pytest
from connector.models import EventIndicator, IndicatorObservable
from pydantic import ValidationError


class TestEventIndicator:
    """Happy/unhappy path coverage for `EventIndicator` construction, including
    its `observables` field_validator - the only custom logic in `models.py`,
    which normalizes OpenCTI's raw `observable_values` extension attribute.
    """

    def test_event_indicator_model_accepts_valid_input(self):
        # Given: a valid, complete set of fields for an EventIndicator
        # When: constructing an EventIndicator
        indicator = EventIndicator(
            id="indicator--id",
            description="Malicious domain",
            observables=[{"type": "Domain-Name", "value": "evil.com"}],
            valid_until="2030-01-01T00:00:00Z",
            score=75,
        )
        # Then: the indicator is constructed successfully, fields cast to
        # their expected Python type
        assert indicator.id == "indicator--id"
        assert indicator.description == "Malicious domain"
        assert indicator.valid_until == datetime(2030, 1, 1, 0, 0, tzinfo=timezone.utc)
        assert indicator.score == 75
        assert indicator.observables == [
            IndicatorObservable(type="Domain-Name", value="evil.com")
        ]

    def test_event_indicator_model_rejects_missing_id(self):
        # Given: no `id` value (e.g. missing extension attribute)
        # When: constructing an EventIndicator
        # Then: a ValidationError is raised, reporting `id` as required
        with pytest.raises(ValidationError, match=r"id\s+Field required"):
            EventIndicator()

    def test_event_indicator_model_flattens_stixfile_hashes_into_one_observable_per_algorithm(
        self,
    ):
        # Given: a raw StixFile observable with multiple hash algorithms
        # When: constructing an EventIndicator
        indicator = EventIndicator(
            id="indicator--id",
            observables=[
                {"type": "StixFile", "hashes": {"MD5": "aaa", "SHA-256": "bbb"}}
            ],
        )
        # Then: one observable per hash algorithm is extracted
        assert indicator.observables == [
            IndicatorObservable(type="StixFile", value="aaa"),
            IndicatorObservable(type="StixFile", value="bbb"),
        ]

    def test_event_indicator_model_skips_stixfile_observable_without_hashes(self):
        # Given: a raw StixFile observable without a "hashes" key
        # When: constructing an EventIndicator
        indicator = EventIndicator(
            id="indicator--id", observables=[{"type": "StixFile"}]
        )
        # Then: no observable is extracted
        assert indicator.observables == []

    def test_event_indicator_model_skips_observable_without_value(self):
        # Given: a raw observable missing its "value" key
        # When: constructing an EventIndicator
        indicator = EventIndicator(
            id="indicator--id", observables=[{"type": "Domain-Name"}]
        )
        # Then: no observable is extracted
        assert indicator.observables == []

    def test_event_indicator_model_defaults_observables_to_empty_list_when_none(self):
        # Given: observables explicitly set to None (e.g. missing extension attribute)
        # When: constructing an EventIndicator
        indicator = EventIndicator(id="indicator--id", observables=None)
        # Then: observables default to an empty list, no error
        assert indicator.observables == []

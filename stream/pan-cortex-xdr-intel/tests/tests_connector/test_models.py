from datetime import datetime, timezone

import pytest
from connector.models import CortexXdrIoc, OctiIndicator, OctiIndicatorObservable
from pydantic import ValidationError


class TestOctiIndicator:
    """Happy/unhappy path coverage for `OctiIndicator` construction, including
    its `observables` field_validator - the only custom logic in `models.py`,
    which normalizes OpenCTI's raw `observable_values` extension attribute.
    """

    def test_event_indicator_model_accepts_valid_input(self):
        # Given: a valid, complete set of fields for an OctiIndicator
        # When: constructing an OctiIndicator
        indicator = OctiIndicator(
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
            OctiIndicatorObservable(type="Domain-Name", value="evil.com")
        ]

    def test_event_indicator_model_rejects_missing_id(self):
        # Given: no `id` value (e.g. missing extension attribute)
        # When: constructing an OctiIndicator
        # Then: a ValidationError is raised, reporting `id` as required
        with pytest.raises(ValidationError, match=r"id\s+Field required"):
            OctiIndicator()

    def test_event_indicator_model_keeps_stixfile_name_and_hashes_on_one_observable(
        self,
    ):
        # Given: a raw StixFile observable with a name and multiple hash algorithms
        # When: constructing an OctiIndicator
        indicator = OctiIndicator(
            id="indicator--id",
            observables=[
                {
                    "type": "StixFile",
                    "name": "evil.exe",
                    "hashes": {"MD5": "aaa", "SHA-256": "bbb"},
                }
            ],
        )
        # Then: a single observable is extracted, with `name` and `hashes` intact
        assert indicator.observables == [
            OctiIndicatorObservable(
                type="StixFile",
                name="evil.exe",
                hashes={"MD5": "aaa", "SHA-256": "bbb"},
            )
        ]

    def test_event_indicator_model_skips_stixfile_observable_without_name_or_hashes(
        self,
    ):
        # Given: a raw StixFile observable without a "name" or "hashes" key
        # When: constructing an OctiIndicator
        indicator = OctiIndicator(
            id="indicator--id", observables=[{"type": "StixFile"}]
        )
        # Then: no observable is extracted
        assert indicator.observables == []

    def test_event_indicator_model_skips_observable_without_value(self):
        # Given: a raw observable missing its "value" key
        # When: constructing an OctiIndicator
        indicator = OctiIndicator(
            id="indicator--id", observables=[{"type": "Domain-Name"}]
        )
        # Then: no observable is extracted
        assert indicator.observables == []

    def test_event_indicator_model_defaults_observables_to_empty_list_when_none(self):
        # Given: observables explicitly set to None (e.g. missing extension attribute)
        # When: constructing an OctiIndicator
        indicator = OctiIndicator(id="indicator--id", observables=None)
        # Then: observables default to an empty list, no error
        assert indicator.observables == []

    def test_event_indicator_model_converts_non_utc_aware_valid_until_to_utc(self):
        # Given: a `valid_until` with a non-UTC UTC offset
        # When: constructing an OctiIndicator
        indicator = OctiIndicator(
            id="indicator--id", valid_until="2030-01-01T12:00:00+02:00"
        )
        # Then: `valid_until` is converted to UTC
        assert indicator.valid_until == datetime(2030, 1, 1, 10, 0, tzinfo=timezone.utc)

    def test_event_indicator_model_treats_naive_valid_until_as_utc(self):
        # Given: a naive (timezone-less) `valid_until`
        # When: constructing an OctiIndicator
        indicator = OctiIndicator(
            id="indicator--id", valid_until=datetime(2030, 1, 1, 12, 0, 0)
        )
        # Then: `valid_until` is assumed to already be UTC, and tagged as such
        assert indicator.valid_until == datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)


class TestCortexXdrIoc:
    """Happy/unhappy path coverage for `CortexXdrIoc` construction."""

    def test_accepts_minimal_valid_input(self):
        # Given: only the required fields
        # When: constructing a CortexXdrIoc
        ioc = CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")
        # Then: the IOC is constructed successfully, optional fields default to None
        assert ioc.indicator == "evil.com"
        assert ioc.type == "DOMAIN_NAME"
        assert ioc.severity is None
        assert ioc.expiration_date is None
        assert ioc.comment is None
        assert ioc.reputation is None
        assert ioc.reliability is None
        assert ioc.rule_id is None

    def test_rejects_invalid_type(self):
        # Given: an unsupported `type` value
        # When: constructing a CortexXdrIoc
        # Then: a ValidationError is raised
        with pytest.raises(ValidationError):
            CortexXdrIoc(indicator="evil.com", type="INVALID")

    def test_accepts_int_expiration_date(self):
        # Given: an `expiration_date` passed as an epoch-millisecond `int`
        # When: constructing a CortexXdrIoc
        ioc = CortexXdrIoc(
            indicator="evil.com", type="DOMAIN_NAME", expiration_date=1893456000000
        )
        # Then: `expiration_date` is left unchanged
        assert ioc.expiration_date == 1893456000000

    def test_accepts_rule_id(self):
        # Given: an existing IOC's `rule_id`
        # When: constructing a CortexXdrIoc
        ioc = CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME", rule_id=42)
        # Then: `rule_id` is set as given
        assert ioc.rule_id == 42

    def test_is_mutable_so_rule_id_can_be_resolved_after_construction(self):
        # Given: a constructed CortexXdrIoc without a `rule_id`
        ioc = CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME")
        # When: mutating `rule_id` in place, as done by
        # `Connector._resolve_xdr_iocs_rule_ids` once the existing IOC is looked up
        ioc.rule_id = 42
        # Then: no error is raised, and the new value is set
        assert ioc.rule_id == 42

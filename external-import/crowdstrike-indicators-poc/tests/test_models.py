"""Tests for the CrowdStrike indicator model."""

from datetime import UTC, datetime

import pytest
from crowdstrike_indicators.entities.models import (
    CrowdStrikeActor,
    CrowdStrikeIndicator,
    CrowdStrikeLabel,
    EnrichedCrowdStrikeIndicator,
)
from pydantic import ValidationError

MINIMAL = {
    "id": "ioc-1",
    "indicator": "evil.example",
    "type": "domain",
    "_marker": "1700000005abc0001",
    "last_updated": 1700000005,
}


def _dump(model: CrowdStrikeIndicator) -> dict:
    return model.model_dump(mode="json", by_alias=True, exclude_unset=True)


def test_minimal_indicator_is_valid():
    model = CrowdStrikeIndicator.model_validate(MINIMAL)
    assert model.id == "ioc-1"
    assert model.marker == "1700000005abc0001"


def test_missing_marker_is_invalid():
    raw = {k: v for k, v in MINIMAL.items() if k != "_marker"}
    with pytest.raises(ValidationError):
        CrowdStrikeIndicator.model_validate(raw)


@pytest.mark.parametrize("marker", ["17000abc", "abc1700000005", ""])
def test_marker_without_ten_leading_digits_is_invalid(marker):
    with pytest.raises(ValidationError):
        CrowdStrikeIndicator.model_validate({**MINIMAL, "_marker": marker})


@pytest.mark.parametrize("missing", ["id", "indicator", "type", "last_updated"])
def test_required_fields(missing):
    raw = {k: v for k, v in MINIMAL.items() if k != missing}
    with pytest.raises(ValidationError):
        CrowdStrikeIndicator.model_validate(raw)


def test_unix_seconds_are_parsed_as_utc():
    model = CrowdStrikeIndicator.model_validate(
        {**MINIMAL, "published_date": 1700000000}
    )
    assert model.last_updated == datetime(2023, 11, 14, 22, 13, 25, tzinfo=UTC)
    assert model.published_date == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)


def test_non_timestamp_last_updated_is_invalid():
    with pytest.raises(ValidationError):
        CrowdStrikeIndicator.model_validate({**MINIMAL, "last_updated": "yesterday"})


def test_unknown_fields_are_kept_and_serialized():
    raw = {
        **MINIMAL,
        "foo": {"bar": 1},
        "reports": ["CSIT-1234"],
        "relations": [{"id": "rel-1", "type": "domain"}],
    }
    model = CrowdStrikeIndicator.model_validate(raw)

    assert model.model_extra == {
        "foo": {"bar": 1},
        "reports": ["CSIT-1234"],
        "relations": [{"id": "rel-1", "type": "domain"}],
    }
    dumped = _dump(model)
    assert dumped["foo"] == {"bar": 1}
    assert dumped["reports"] == ["CSIT-1234"]
    assert dumped["relations"] == [{"id": "rel-1", "type": "domain"}]


def test_serialization_uses_api_names_and_adds_nothing():
    dumped = _dump(CrowdStrikeIndicator.model_validate(MINIMAL))

    assert set(dumped) == set(MINIMAL)
    assert dumped["_marker"] == "1700000005abc0001"
    assert "marker" not in dumped
    assert dumped["last_updated"] == "2023-11-14T22:13:25Z"


def test_absent_optional_field_stays_absent_but_explicit_values_are_kept():
    raw = {**MINIMAL, "actors": [], "deleted": False, "published_date": None}
    dumped = _dump(CrowdStrikeIndicator.model_validate(raw))

    assert dumped["actors"] == []
    assert dumped["deleted"] is False
    assert dumped["published_date"] is None
    assert "malware_families" not in dumped


def test_labels():
    raw = {
        **MINIMAL,
        "labels": [
            {
                "name": "MaliciousConfidence/High",
                "created_on": 1700000000,
                "last_valid_on": 1700000005,
            },
            {"name": "ThreatType/Criminal"},
        ],
    }
    model = CrowdStrikeIndicator.model_validate(raw)

    assert model.labels is not None
    assert isinstance(model.labels[0], CrowdStrikeLabel)
    assert model.labels[0].created_on == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert model.labels[1].last_valid_on is None
    assert _dump(model)["labels"][1] == {"name": "ThreatType/Criminal"}


def test_label_without_name_is_invalid():
    with pytest.raises(ValidationError):
        CrowdStrikeIndicator.model_validate({**MINIMAL, "labels": [{"x": 1}]})


# --- Actors ----------------------------------------------------------------

MINIMAL_ACTOR = {"id": 123, "name": "SALTY SPIDER"}


def test_minimal_actor_is_valid():
    actor = CrowdStrikeActor.model_validate(MINIMAL_ACTOR)
    assert actor.id == 123
    assert actor.name == "SALTY SPIDER"


@pytest.mark.parametrize("missing", ["id", "name"])
def test_actor_missing_required_field_is_invalid(missing):
    raw = {k: v for k, v in MINIMAL_ACTOR.items() if k != missing}
    with pytest.raises(ValidationError):
        CrowdStrikeActor.model_validate(raw)


def test_unknown_actor_field_is_kept_on_serialization():
    actor = CrowdStrikeActor.model_validate({**MINIMAL_ACTOR, "foo": {"bar": 1}})
    assert _dump(actor)["foo"] == {"bar": 1}


def test_actor_activity_dates_are_aware_datetimes():
    actor = CrowdStrikeActor.model_validate(
        {**MINIMAL_ACTOR, "first_activity_date": 1700000005, "last_activity_date": 0}
    )
    assert actor.first_activity_date == datetime(2023, 11, 14, 22, 13, 25, tzinfo=UTC)
    assert actor.last_activity_date == datetime(1970, 1, 1, tzinfo=UTC)


def test_actor_lists_of_unknown_shape_are_kept_verbatim():
    raw = {
        **MINIMAL_ACTOR,
        "known_as": "Salty, Pepper Spider",
        "motivations": [{"id": 1, "slug": "criminal", "value": "Criminal"}],
        "objectives": [{"id": 2, "slug": "money", "value": "Money"}],
    }
    dumped = _dump(CrowdStrikeActor.model_validate(raw))
    for field in ("known_as", "motivations", "objectives"):
        assert dumped[field] == raw[field]


# --- Enriched indicators ---------------------------------------------------


def test_enriched_indicator_defaults_to_no_actor():
    enriched = EnrichedCrowdStrikeIndicator.model_validate(MINIMAL)
    assert enriched.actor_objects_list == []
    assert "actor_objects_list" not in _dump(enriched)


def test_enriched_indicator_validates_actor_dicts():
    enriched = EnrichedCrowdStrikeIndicator.model_validate(
        {**MINIMAL, "actor_objects_list": [MINIMAL_ACTOR]}
    )
    assert enriched.actor_objects_list == [CrowdStrikeActor(**MINIMAL_ACTOR)]
    assert _dump(enriched)["actor_objects_list"] == [MINIMAL_ACTOR]


def test_enriched_indicator_rejects_an_invalid_actor():
    with pytest.raises(ValidationError):
        EnrichedCrowdStrikeIndicator.model_validate(
            {**MINIMAL, "actor_objects_list": [{"id": 1}]}
        )


def test_enriched_indicator_is_an_indicator():
    assert issubclass(EnrichedCrowdStrikeIndicator, CrowdStrikeIndicator)

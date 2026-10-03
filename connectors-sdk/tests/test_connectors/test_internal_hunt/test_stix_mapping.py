# pragma: no cover
# type: ignore
"""Tests of the STIX mapping of telemetry hunt results."""

from datetime import datetime, timezone

from connectors_sdk.connectors.internal_hunt import (
    HuntRequest,
    ObservableValue,
    build_telemetry_objects,
    hunt_author,
    hunt_markings,
)
from connectors_sdk.models import ObservedData, Sighting

FIRST = datetime(2026, 10, 3, 1, tzinfo=timezone.utc)
LAST = datetime(2026, 10, 3, 5, tzinfo=timezone.utc)


def test_build_telemetry_objects_maps_sightings_and_observed_data(hunt_event):
    # Given a hunt run with one technique, one indicator and extracted observables
    request = HuntRequest.model_validate(hunt_event())
    observables = [
        ObservableValue("IPv4-Addr", "8.8.8.8", count=3),
        ObservableValue("Domain-Name", "evil.com"),
    ]

    # When the knowledge of the run is built
    objects = build_telemetry_objects(request, 7, FIRST, LAST, observables)
    stix = [obj.to_stix2_object() for obj in objects]
    by_type = {}
    for item in stix:
        by_type.setdefault(item["type"], []).append(item)

    # Then observables, one observed-data and one sighting per technique and indicator are produced
    assert len(by_type["ipv4-addr"]) == 1
    assert len(by_type["domain-name"]) == 1
    observed = by_type["observed-data"][0]
    assert observed["number_observed"] == 7
    assert set(observed["object_refs"]) == {
        by_type["ipv4-addr"][0]["id"],
        by_type["domain-name"][0]["id"],
    }
    sightings = by_type["sighting"]
    assert {s["sighting_of_ref"] for s in sightings} == {
        request.hunt.techniques[0].standard_id,
        request.hunt.indicators[0].standard_id,
    }
    for sighting in sightings:
        assert sighting["where_sighted_refs"] == [request.security_platform.standard_id]
        assert sighting["count"] == 7
        assert sighting["first_seen"] == FIRST
        assert sighting["last_seen"] == LAST
        assert "run-1" in sighting["description"]
        assert sighting["created_by_ref"] == request.hunt.created_by_ref
        assert sighting["object_marking_refs"] == request.hunt.object_marking_refs
    assert isinstance(objects[-1], Sighting)
    assert any(isinstance(obj, ObservedData) for obj in objects)


def test_build_telemetry_objects_is_deterministic(hunt_event):
    # Given the same run mapped twice
    request = HuntRequest.model_validate(hunt_event())
    observables = [ObservableValue("IPv4-Addr", "8.8.8.8")]

    # When/Then the STIX ids are identical (re-runs upsert)
    first = [
        o.id for o in build_telemetry_objects(request, 1, FIRST, LAST, observables)
    ]
    second = [
        o.id for o in build_telemetry_objects(request, 1, FIRST, LAST, observables)
    ]
    assert first == second


def test_build_telemetry_objects_without_hits_or_platform(hunt_event):
    # Given runs without hits, or without Security Platform and author/markings
    request = HuntRequest.model_validate(hunt_event())
    anonymous = HuntRequest.model_validate(
        hunt_event(
            hunt={"created_by_ref": None, "object_marking_refs": []},
            security_platform=None,
        )
    )

    # When/Then no knowledge is produced without hits, and no sighting without platform
    assert build_telemetry_objects(request, 0, FIRST, LAST, []) == []
    objects = build_telemetry_objects(
        anonymous, 2, FIRST, LAST, [ObservableValue("IPv4-Addr", "8.8.8.8")]
    )
    assert [type(o).__name__ for o in objects] == ["IPV4Address", "ObservedData"]
    assert hunt_author(anonymous) is None
    assert hunt_markings(anonymous) == []
    assert objects[1].markings is None


def test_build_telemetry_objects_without_observables_only_sights(hunt_event):
    # Given a run with hits but no observable
    request = HuntRequest.model_validate(hunt_event())

    # When/Then only sightings are produced
    objects = build_telemetry_objects(request, 3, FIRST, LAST, [])
    assert [type(o).__name__ for o in objects] == ["Sighting", "Sighting"]

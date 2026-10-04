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

    # Then observables, one observed-data per observable and one sighting per
    # technique and indicator are produced
    assert len(by_type["ipv4-addr"]) == 1
    assert len(by_type["domain-name"]) == 1
    most_observed, least_observed = by_type["observed-data"]
    assert most_observed["number_observed"] == 3
    assert most_observed["object_refs"] == [by_type["ipv4-addr"][0]["id"]]
    assert least_observed["number_observed"] == 1
    assert least_observed["object_refs"] == [by_type["domain-name"][0]["id"]]
    for observed in by_type["observed-data"]:
        assert observed["x_opencti_hunt_run_id"] == request.hunt_run.id
        assert observed["first_observed"] == FIRST
        assert observed["last_observed"] == LAST
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
        assert sighting["x_opencti_hunt_run_id"] == request.hunt_run.id
        assert sighting["created_by_ref"] == request.hunt.created_by_ref
        assert sighting["object_marking_refs"] == request.hunt.object_marking_refs
    assert isinstance(objects[-1], Sighting)
    assert any(isinstance(obj, ObservedData) for obj in objects)


def test_a_retry_upserts_the_knowledge_of_its_run(hunt_event):
    # Given two attempts of one run: the second sees more events, so the counts
    # and the time bounds of its observables move
    request = HuntRequest.model_validate(hunt_event())
    first = build_telemetry_objects(
        request,
        2,
        FIRST,
        LAST,
        [
            ObservableValue("IPv4-Addr", "8.8.8.8"),
            ObservableValue("Domain-Name", "evil.com"),
        ],
    )
    later = datetime(2026, 10, 3, 9, tzinfo=timezone.utc)
    second = build_telemetry_objects(
        request,
        5,
        FIRST,
        later,
        [
            ObservableValue("IPv4-Addr", "8.8.8.8", count=4),
            ObservableValue("Domain-Name", "evil.com"),
        ],
    )

    # When/Then both attempts produce the same observed-data and sightings:
    # the retry upserts them instead of adding new ones
    def ids(objects, stix_type):
        return {obj.id for obj in objects if obj.to_stix2_object()["type"] == stix_type}

    assert len(ids(first, "observed-data")) == 2
    assert ids(first, "observed-data") == ids(second, "observed-data")
    assert ids(first, "sighting") == ids(second, "sighting")


def test_build_telemetry_objects_is_deterministic_per_run(hunt_event):
    # Given a run mapped twice (a retry) and another run with the same results
    request = HuntRequest.model_validate(hunt_event())
    retry = HuntRequest.model_validate(
        hunt_event(hunt_run={"id": "run-1", "attempt": 2, "trigger": "retry"})
    )
    other_run = HuntRequest.model_validate(
        hunt_event(hunt_run={"id": "run-2", "attempt": 1, "trigger": "schedule"})
    )
    observables = [ObservableValue("IPv4-Addr", "8.8.8.8")]

    # When the knowledge of each run is built
    def ids(run: HuntRequest) -> list[str]:
        return [o.id for o in build_telemetry_objects(run, 1, FIRST, LAST, observables)]

    first, again, other = ids(request), ids(retry), ids(other_run)

    # Then a retry upserts the same objects, and another run only shares the observable
    assert first == again
    assert first[0] == other[0] and first[0].startswith("ipv4-addr--")
    assert set(first[1:]).isdisjoint(other[1:])


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

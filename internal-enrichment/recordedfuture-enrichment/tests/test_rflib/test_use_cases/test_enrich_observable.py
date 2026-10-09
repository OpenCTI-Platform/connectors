from unittest.mock import Mock

import pytest
from connectors_sdk.models import (
    URL,
    DomainName,
    File,
    Indicator,
    IPV4Address,
    IPV6Address,
    Malware,
    Note,
    Organization,
    Relationship,
)
from connectors_sdk.models.enums import TLPLevel
from rf_client.models import ObservableEnrichment
from rflib.use_cases.enrich_observable import ObservableEnricher


def make_enrichment(
    value: str = "185.177.72.17",
    entity_type: str = "IpAddress",
    risk_score: int | None = 5,
) -> ObservableEnrichment:
    return ObservableEnrichment(
        entity={"id": "ip:" + value, "name": value, "type": entity_type},
        risk={
            "score": risk_score,
            "evidenceDetails": [
                {
                    "rule": "Historical Suspected C&C Server",
                    "evidenceString": "1 sighting on 1 source.",
                    "timestamp": "2026-07-01T00:00:00.000Z",
                }
            ],
        },
        links=[
            {"type": "type:Malware", "name": "Cobalt Strike", "attributes": []},
            {"type": "type:Organization", "name": "ACME", "attributes": []},
            {"type": "type:URL", "name": "http://example.com/", "attributes": []},
        ],
    )


def make_enricher(threshold: int) -> ObservableEnricher:
    helper = Mock()
    helper.connector_logger = Mock()
    return ObservableEnricher(
        helper=helper,
        tlp_level=TLPLevel.AMBER_STRICT,
        indicator_creation_threshold=threshold,
    )


def get_relationship(octi_objects, relationship_type, source, target):
    return next(
        (
            obj
            for obj in octi_objects
            if isinstance(obj, Relationship)
            and obj.type == relationship_type
            and obj.source.id == source.id
            and obj.target.id == target.id
        ),
        None,
    )


def test_enrichment_above_threshold_creates_indicator():
    enricher = make_enricher(threshold=0)

    octi_objects = enricher.process_observable_enrichment(make_enrichment())

    observable = next(
        obj
        for obj in octi_objects
        if isinstance(obj, IPV4Address) and obj.value == "185.177.72.17"
    )
    indicator = next(
        obj
        for obj in octi_objects
        if isinstance(obj, Indicator) and obj.name == "185.177.72.17"
    )
    malware = next(obj for obj in octi_objects if isinstance(obj, Malware))
    assert get_relationship(octi_objects, "based-on", indicator, observable)
    assert get_relationship(octi_objects, "indicates", indicator, malware)
    for note in (obj for obj in octi_objects if isinstance(obj, Note)):
        assert observable.id in [obj.id for obj in note.objects]
    # every object must convert to STIX
    for obj in octi_objects:
        obj.to_stix2_object()


@pytest.mark.parametrize(
    "entity_type,value,observable_type,pattern_prefix",
    [
        (
            "Hash",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            File,
            "[file:hashes.",
        ),
        ("InternetDomainName", "example.org", DomainName, "[domain-name:value"),
        ("IpAddress", "2001:db8::1", IPV6Address, "[ipv6-addr:value"),
        ("URL", "https://example.org/malicious", URL, "[url:value"),
    ],
)
@pytest.mark.parametrize("threshold,creates_indicator", [(0, True), (50, False)])
def test_enrichment_of_entity_types(
    entity_type, value, observable_type, pattern_prefix, threshold, creates_indicator
):
    enricher = make_enricher(threshold=threshold)

    octi_objects = enricher.process_observable_enrichment(
        make_enrichment(value=value, entity_type=entity_type)
    )

    observable = next(
        obj
        for obj in octi_objects
        if isinstance(obj, observable_type)
        and value in (obj.hashes.values() if isinstance(obj, File) else [obj.value])
    )
    indicator = next(
        (
            obj
            for obj in octi_objects
            if isinstance(obj, Indicator) and obj.name == value
        ),
        None,
    )
    if creates_indicator:
        assert indicator.pattern.startswith(pattern_prefix)
        assert get_relationship(octi_objects, "based-on", indicator, observable)
    else:
        assert indicator is None
    for obj in octi_objects:
        obj.to_stix2_object()


def test_enrichment_below_threshold_does_not_create_indicator():
    """Regression test for https://github.com/OpenCTI-Platform/connectors/issues/7093."""
    enricher = make_enricher(threshold=50)

    octi_objects = enricher.process_observable_enrichment(make_enrichment())

    observable = next(
        obj
        for obj in octi_objects
        if isinstance(obj, IPV4Address) and obj.value == "185.177.72.17"
    )
    assert not any(
        isinstance(obj, Indicator) and obj.name == "185.177.72.17"
        for obj in octi_objects
    )
    malware = next(obj for obj in octi_objects if isinstance(obj, Malware))
    organization = next(
        obj
        for obj in octi_objects
        if isinstance(obj, Organization) and obj.name == "ACME"
    )
    assert get_relationship(octi_objects, "related-to", observable, malware)
    assert get_relationship(octi_objects, "related-to", organization, observable)
    # linked observables still get their own indicator
    linked_url = next(obj for obj in octi_objects if isinstance(obj, URL))
    linked_indicator = next(
        obj
        for obj in octi_objects
        if isinstance(obj, Indicator) and obj.name == "http://example.com/"
    )
    assert get_relationship(octi_objects, "based-on", linked_indicator, linked_url)
    # notes are attached to the enriched observable so they show up on it
    notes = [obj for obj in octi_objects if isinstance(obj, Note)]
    assert len(notes) == 2
    for note in notes:
        assert observable.id in [obj.id for obj in note.objects]
    for obj in octi_objects:
        obj.to_stix2_object()


def test_enrichment_without_risk_score():
    enricher = make_enricher(threshold=0)

    octi_objects = enricher.process_observable_enrichment(
        make_enrichment(risk_score=None)
    )

    assert any(isinstance(obj, IPV4Address) for obj in octi_objects)
    assert not any(
        isinstance(obj, Indicator) and obj.name == "185.177.72.17"
        for obj in octi_objects
    )
    for obj in octi_objects:
        obj.to_stix2_object()


@pytest.mark.parametrize("threshold", [0, 50])
def test_enrichment_of_unsupported_entity_type(threshold):
    enricher = make_enricher(threshold=threshold)

    octi_objects = enricher.process_observable_enrichment(
        make_enrichment(value="foo", entity_type="Unsupported")
    )

    assert not any(
        isinstance(obj, Relationship) and obj.source is None for obj in octi_objects
    )
    for obj in octi_objects:
        obj.to_stix2_object()


@pytest.mark.parametrize("risk_score", [5, None])
def test_enrichment_without_indicator_ignores_invalid_indicator_pattern(risk_score):
    """An indicator that is not created must not abort the enrichment."""
    enricher = make_enricher(threshold=50)

    octi_objects = enricher.process_observable_enrichment(
        make_enrichment(
            value="https://example.com/o'reilly",
            entity_type="URL",
            risk_score=risk_score,
        )
    )

    assert any(
        isinstance(obj, URL) and obj.value == "https://example.com/o'reilly"
        for obj in octi_objects
    )
    assert not any(
        isinstance(obj, Indicator) and "reilly" in obj.name for obj in octi_objects
    )

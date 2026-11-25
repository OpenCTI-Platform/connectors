"""Tests of `IPv4Processor`, the example processor.

These tests do not call the real API: the client is a mock. They call
`collect()` and `transform()` directly, like the connector does.

Do not test the scope, the TLP, the playbooks or the bundle here: the
connector handles them, and `connectors-sdk` already tests them.

TODO:
    - [ ] Replace these tests with tests of your own processors.
"""

from unittest.mock import MagicMock

import pytest
from connector.enrichment_processors import IPv4Processor
from connectors_sdk import ApiNotFoundError, BaseEnrichmentProcessor
from connectors_sdk.models import (
    AutonomousSystem,
    IPV4Address,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from template_client import IPReputation


@pytest.fixture
def processor(connector_settings) -> IPv4Processor:
    """An `IPv4Processor` ready to use, with a mock API client."""
    processor = IPv4Processor()
    processor.inject_dependencies(settings=connector_settings)
    processor.post_init()
    processor.client = MagicMock()
    return processor


def test_ipv4_processor_should_be_an_enrichment_processor():
    """Test that `IPv4Processor` implements the `BaseEnrichmentProcessor` contract."""
    assert issubclass(IPv4Processor, BaseEnrichmentProcessor)
    IPv4Processor()  # raises if `collect` or `transform` is missing


def test_collect_should_return_the_ip_reputation(processor, ipv4_message):
    """Test that `collect()` returns the data of the API for the entity value."""
    # Given: the API knows the IP
    reputation = IPReputation(ip="1.2.3.4", score=80)
    processor.client.get_ip_reputation.return_value = reputation

    # When: the data is collected
    data = processor.collect(ipv4_message)

    # Then: the API is called with the IP value, and its data is returned
    processor.client.get_ip_reputation.assert_called_once_with("1.2.3.4")
    assert data == reputation


def test_collect_should_return_none_when_the_ip_is_unknown(processor, ipv4_message):
    """Test that an unknown IP (HTTP 404) is not an error."""
    # Given: the API does not know the IP
    processor.client.get_ip_reputation.side_effect = ApiNotFoundError("Not found")

    # When: the data is collected
    data = processor.collect(ipv4_message)

    # Then: there is no data, and no error
    assert data is None


def test_transform_should_return_nothing_without_data(processor, ipv4_message):
    """Test that `transform()` returns no object when there is no data."""
    assert processor.transform(data=None, message=ipv4_message) == []


def test_transform_should_enrich_the_entity_and_link_new_objects(
    processor, ipv4_message
):
    """Test that `transform()` returns the enriched entity, with the same id,
    the new objects linked to it, the author and the marking."""
    # Given: the API returns a reputation with an autonomous system
    reputation = IPReputation(
        ip="1.2.3.4", score=80, tags=["scanner"], asn=64496, as_name="Example AS"
    )

    # When: the data is converted
    stix_objects = processor.transform(data=reputation, message=ipv4_message)

    # Then: the author and the marking are returned
    assert any(isinstance(obj, OrganizationAuthor) for obj in stix_objects)
    assert any(isinstance(obj, TLPMarking) for obj in stix_objects)

    # Then: the enriched entity keeps the id of the entity received
    [enriched_ip] = [obj for obj in stix_objects if isinstance(obj, IPV4Address)]
    assert enriched_ip.id == ipv4_message.stix_entity.id
    assert enriched_ip.score == 80
    assert enriched_ip.labels == ["scanner"]
    assert enriched_ip.author is None  # keep the author of the entity
    assert enriched_ip.markings is None  # keep the markings of the entity

    # Then: the autonomous system is linked to the entity received
    [autonomous_system] = [
        obj for obj in stix_objects if isinstance(obj, AutonomousSystem)
    ]
    [relationship] = [obj for obj in stix_objects if isinstance(obj, Relationship)]
    assert relationship.source.id == ipv4_message.stix_entity.id
    assert relationship.target.id == autonomous_system.id


def test_transform_should_not_create_an_autonomous_system_without_asn(
    processor, ipv4_message
):
    """Test that no autonomous system is created when the API returns none."""
    # Given: the API returns a reputation without an autonomous system
    reputation = IPReputation(ip="1.2.3.4", score=10)

    # When: the data is converted
    stix_objects = processor.transform(data=reputation, message=ipv4_message)

    # Then: only the author, the marking and the enriched entity are returned
    assert len(stix_objects) == 3
    assert not any(isinstance(obj, AutonomousSystem) for obj in stix_objects)


def test_transform_should_not_create_an_autonomous_system_when_disabled(
    connector_settings, ipv4_message
):
    """Test that `create_autonomous_system=False` disables the autonomous system."""
    # Given: the creation of autonomous systems is disabled (settings are frozen:
    # change a copy)
    template_config = connector_settings.template.model_copy(
        update={"create_autonomous_system": False}
    )
    settings = connector_settings.model_copy(update={"template": template_config})
    processor = IPv4Processor()
    processor.inject_dependencies(settings=settings)
    processor.post_init()
    reputation = IPReputation(ip="1.2.3.4", score=80, asn=64496)

    # When: the data is converted
    stix_objects = processor.transform(data=reputation, message=ipv4_message)

    # Then: no autonomous system is created
    assert not any(isinstance(obj, AutonomousSystem) for obj in stix_objects)

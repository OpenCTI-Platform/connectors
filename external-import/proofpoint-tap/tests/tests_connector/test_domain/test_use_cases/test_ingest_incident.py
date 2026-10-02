# pragma: no cover # do not include tests modules in coverage metrics
"""Test the ingest incident use case."""

from datetime import datetime, timezone
from typing import Any, Literal, Optional

import pytest
from pydantic import ValidationError
from stix2.v21.base import _STIXBase21

from proofpoint_tap.domain.models.octi.common import TLPMarking
from proofpoint_tap.domain.models.octi.domain import Incident, OrganizationAuthor
from proofpoint_tap.domain.models.octi.observables import EmailAddress, EmailMessage
from proofpoint_tap.domain.models.octi.relationships import (
    EmailAddressRelatedToIncident,
    EmailMessageRelatedToIncident,
)
from proofpoint_tap.domain.use_cases.ingest_incident import IncidentProcessor
from proofpoint_tap.ports.event import ClickEventPort, EventThreatPort, MessageEventPort


class DummyEventThreatAdapter(EventThreatPort):
    """Dummy event threat adapter."""

    def __init__(self):
        """Initialize the adapter."""
        pass

    @property
    def name(self) -> str:
        """Get the threat name."""
        return "threat_name"

    @property
    def type(self) -> str:
        """Get the threat type."""
        return "url"

    @property
    def info_url(self) -> str:
        """Get the threat info URL."""
        return "http://threat.info"

    @property
    def classification(self) -> str:
        """Get the threat classification."""
        return "active"


class DummyClickEventAdapter(ClickEventPort):
    """Dummy click event adapter."""

    def __init__(self):
        """Initialize the adapter."""
        pass

    @property
    def id(self) -> Optional[str]:
        """Get the event ID."""
        return "event_id_123"

    @property
    def guid(self) -> str:
        """Get the event GUID."""
        return "guid_456"

    @property
    def type(
        self,
    ) -> Literal[
        "Message Blocked", "Click Blocked", "Message Delivered", "Click Permitted"
    ]:
        """Get the event type."""
        return "Click Blocked"

    @property
    def time(self) -> "datetime":
        """Get the event time."""
        return datetime.now(tz=timezone.utc)

    @property
    def threats(self) -> Optional[list[EventThreatPort]]:
        """Get the threats."""
        return [DummyEventThreatAdapter()]

    @property
    def sender_address(self) -> str:
        """Get the message sender address."""
        return "sender@example.com"

    @property
    def recipients(self) -> Optional[list[str]]:
        """Get the message recipients."""
        return ["recipient1@example.com", "recipient2@example.com"]

    @property
    def click_ip(self) -> str:
        """Get the click IP address."""
        return "192.168.1.1"

    @property
    def user_agent(self) -> str:
        """Get the click user agent."""
        return "Mozilla/5.0"

    @property
    def url(self) -> str:
        """Get the click URL."""
        return "http://example.com"

    @property
    def message_id(self) -> Optional[str]:
        """Get the click message ID."""
        return "message_id_789"


_UNSET = object()

_DEFAULT_SENDER = "sender@example.com"
_DEFAULT_RECIPIENTS = ["recipient1@example.com", "recipient2@example.com"]
_DEFAULT_FROM_ADDRESSES = ["from_address1@example.com", "from_address2@example.com"]
_DEFAULT_TO_ADDRESSES = ["to_address1@example.com", "to_address2@example.com"]
_DEFAULT_CC_ADDRESSES = ["cc_address1@example.com", "cc_address2@example.com"]
_ADDRESS_FIELD_ORDER = (
    "sender_address",
    "from_addresses",
    "to_addresses",
    "recipients",
    "cc_addresses",
)
_DEFAULT_ADDRESSES_BY_FIELD = {
    "sender_address": [_DEFAULT_SENDER],
    "from_addresses": _DEFAULT_FROM_ADDRESSES,
    "to_addresses": _DEFAULT_TO_ADDRESSES,
    "recipients": _DEFAULT_RECIPIENTS,
    "cc_addresses": _DEFAULT_CC_ADDRESSES,
}
_DEFAULT_OBSERVED_ADDRESS_VALUES = [
    address
    for field_name in _ADDRESS_FIELD_ORDER
    for address in _DEFAULT_ADDRESSES_BY_FIELD[field_name]
]
_INVALID_ADDRESS_VALUES = [
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace"),
    pytest.param("not-an-email", id="missing-at"),
    pytest.param("info@[e051.Bunnings.com]", id="bracketed-domain"),
]


class DummyMessageEventAdapter(MessageEventPort):
    """Dummy message event adapter."""

    def __init__(
        self,
        sender_address: str = _DEFAULT_SENDER,
        recipients: Any = _UNSET,
        from_addresses: Any = _UNSET,
        to_addresses: Any = _UNSET,
        cc_addresses: Any = _UNSET,
        subject: Any = "Test Subject",
    ):
        """Initialize the adapter."""
        self._sender_address = sender_address
        self._recipients = (
            list(_DEFAULT_RECIPIENTS) if recipients is _UNSET else recipients
        )
        self._from_addresses = (
            list(_DEFAULT_FROM_ADDRESSES)
            if from_addresses is _UNSET
            else from_addresses
        )
        self._to_addresses = (
            list(_DEFAULT_TO_ADDRESSES) if to_addresses is _UNSET else to_addresses
        )
        self._cc_addresses = (
            list(_DEFAULT_CC_ADDRESSES) if cc_addresses is _UNSET else cc_addresses
        )
        self._subject = subject

    @property
    def id(self) -> Optional[str]:
        """Get the event ID."""
        return "message_event_id_123"

    @property
    def guid(self) -> str:
        """Get the event GUID."""
        return "message_guid_456"

    @property
    def type(
        self,
    ) -> Literal[
        "Message Blocked", "Click Blocked", "Message Delivered", "Click Permitted"
    ]:
        """Get the event type."""
        return "Message Delivered"

    @property
    def time(self) -> "datetime":
        """Get the event time."""
        return datetime.now(tz=timezone.utc)

    @property
    def threats(self) -> Optional[list[EventThreatPort]]:
        """Get the threats."""
        return [DummyEventThreatAdapter()]

    @property
    def sender_address(self) -> str:
        """Get the message sender address."""
        return self._sender_address

    @property
    def recipients(self) -> Optional[list[str]]:
        """Get the message recipients."""
        return self._recipients

    @property
    def queue_id(self) -> str:
        """Get the message queue ID."""
        return "queue_id_789"

    @property
    def spam_score(self) -> Optional[int]:
        """Get the message spam score."""
        return 5

    @property
    def impostor_score(self) -> Optional[int]:
        """Get the message impostor score."""
        return 3

    @property
    def malware_score(self) -> Optional[int]:
        """Get the message malware score."""
        return 0

    @property
    def phish_score(self) -> Optional[int]:
        """Get the message phish score."""
        return 50

    @property
    def cluster_name(self) -> Optional[str]:
        """Get the message cluster name."""
        return "cluster_name_123"

    @property
    def quarantine_folder(self) -> Optional[str]:
        """Get the message quarantine folder."""
        return "quarantine_folder_456"

    @property
    def quarantine_rule(self) -> Optional[str]:
        """Get the message quarantine rule."""
        return "quarantine_rule_789"

    @property
    def policy_routes(self) -> Optional[list[str]]:
        """Get the message policy routes."""
        return ["policy_route_1", "policy_route_2"]

    @property
    def module_runs(self) -> Optional[list[str]]:
        """Get the modules that processed the message."""
        return ["module_run_1", "module_run_2"]

    @property
    def completely_rewritten(self) -> Optional[bool]:
        """Get the message completely rewritten status."""
        return False

    @property
    def from_addresses(self) -> Optional[list[str]]:
        """Get the message from addresses."""
        return self._from_addresses

    @property
    def to_addresses(self) -> Optional[list[str]]:
        """Get the message to addresses."""
        return self._to_addresses

    @property
    def cc_addresses(self) -> Optional[list[str]]:
        """Get the message cc addresses."""
        return self._cc_addresses

    @property
    def subject(self) -> Optional[str]:
        """Get the message subject."""
        return self._subject


def _email_addresses(entities: list[Any]) -> list[EmailAddress]:
    """Return email address observables in emission order."""
    return [entity for entity in entities if isinstance(entity, EmailAddress)]


def _stix_reference_ids(stix_object: _STIXBase21) -> list[str]:
    """Collect identifier references stored on a STIX object."""
    reference_ids: list[str] = []
    for key, value in dict(stix_object).items():
        if not isinstance(key, str):
            continue
        if key.endswith("_ref") and isinstance(value, str):
            reference_ids.append(value)
        elif key.endswith("_refs") and isinstance(value, list):
            reference_ids.extend(item for item in value if isinstance(item, str))
    return reference_ids


def _assert_entities_serialize_without_dangling_references(
    entities: list[Any],
) -> None:
    """Serialize every entity and require each STIX reference to resolve in-bundle."""
    stix_objects = [entity.to_stix2_object() for entity in entities]
    assert all(  # noqa: S101
        isinstance(stix_object, _STIXBase21) for stix_object in stix_objects
    )
    known_ids = {stix_object["id"] for stix_object in stix_objects}
    for stix_object in stix_objects:
        for reference_id in _stix_reference_ids(stix_object):
            assert reference_id in known_ids  # noqa: S101


def _assert_address_values_and_relationship_sources(
    entities: list[Any], expected_values: list[str]
) -> None:
    """Assert surviving addresses and their incident relationships keep input order."""
    addresses = _email_addresses(entities)
    relationships = [
        entity
        for entity in entities
        if isinstance(entity, EmailAddressRelatedToIncident)
    ]
    assert [address.value for address in addresses] == expected_values  # noqa: S101
    assert [relationship.source.id for relationship in relationships] == [  # noqa: S101
        address.id for address in addresses
    ]


def _assert_message_incident_bundle(entities: list[Any]) -> EmailMessage:
    """Assert the incident, message, relationship, author, and marking are present."""
    incidents = [entity for entity in entities if isinstance(entity, Incident)]
    messages = [entity for entity in entities if isinstance(entity, EmailMessage)]
    message_relationships = [
        entity
        for entity in entities
        if isinstance(entity, EmailMessageRelatedToIncident)
    ]
    assert len(incidents) == 1  # noqa: S101
    assert len(messages) == 1  # noqa: S101
    assert len(message_relationships) == 1  # noqa: S101
    assert message_relationships[0].source.id == messages[0].id  # noqa: S101
    assert message_relationships[0].target.id == incidents[0].id  # noqa: S101
    assert (  # noqa: S101
        len([entity for entity in entities if isinstance(entity, OrganizationAuthor)])
        == 1
    )
    assert (  # noqa: S101
        len([entity for entity in entities if isinstance(entity, TLPMarking)]) == 1
    )
    return messages[0]


def _expected_addresses_without(field_name: str) -> list[str]:
    """Return the default valid addresses with one field removed, in emission order."""
    values: list[str] = []
    for name in _ADDRESS_FIELD_ORDER:
        if name != field_name:
            values.extend(_DEFAULT_ADDRESSES_BY_FIELD[name])
    return values


def test_incident_processor_can_prcoess_click_event():
    """Test the incident processor can process a click event."""
    # Given a click event adapter
    adapter = DummyClickEventAdapter()
    # When running the processor on the adapter
    processor = IncidentProcessor(tlp_marking_name="white")
    entities = processor.run_on_event(adapter)
    # Then the entities should be returned
    ## - 1 Incident entity
    assert (  # noqa: S101 # We indeed call assert in unit tests.
        len([entity for entity in entities if entity.__class__.__name__ == "Incident"])
        == 1
    )
    ## - 3 EmailAddress entities (1 sender 2 recipients)
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailAddress"
            ]
        )
        == 3
    )
    ## - 3 EmailAddressRelatedToIncident relationships
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailAddressRelatedToIncident"
            ]
        )
        == 3
    )
    ## - 1 Author
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "OrganizationAuthor"
            ]
        )
        == 1
    )
    # - 1 TLP Marking
    assert (  # noqa: S101
        len(
            [entity for entity in entities if entity.__class__.__name__ == "TLPMarking"]
        )
        == 1
    )
    ## Total 9 entities
    assert len(entities) == 9  # noqa: S101

    ## Than can all be converted to stix object
    # all stix2 lib object
    assert all(  # noqa: S101
        isinstance(entity.to_stix2_object(), _STIXBase21) for entity in entities
    )


def test_incident_processor_can_prcoess_message_event():
    """Test the incident processor can process a message event."""
    # Given a message event adapter
    adapter = DummyMessageEventAdapter()
    # When running the processor on the adapter
    processor = IncidentProcessor(tlp_marking_name="white")
    entities = processor.run_on_event(adapter)
    # Then the entities should be returned
    ## - 1 Incident entity
    assert (  # noqa: S101 # We indeed call assert in unit tests.
        len([entity for entity in entities if entity.__class__.__name__ == "Incident"])
        == 1
    )
    ## - 9 EmailAddress entities (1 sender, 2 recipients, 2 from, 2 to, 2 cc)
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailAddress"
            ]
        )
        == 9
    )
    ## - 9 EmailAddressRelatedToIncident relationships
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailAddressRelatedToIncident"
            ]
        )
        == 9
    )
    ## - 1 EmailMessage entity
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailMessage"
            ]
        )
        == 1
    )
    ## - 1 EmailMessageRelatedToIncident relationship
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "EmailMessageRelatedToIncident"
            ]
        )
        == 1
    )
    ## - 1 Author
    assert (  # noqa: S101
        len(
            [
                entity
                for entity in entities
                if entity.__class__.__name__ == "OrganizationAuthor"
            ]
        )
        == 1
    )
    ## - 1 TLP Marking
    assert (  # noqa: S101
        len(
            [entity for entity in entities if entity.__class__.__name__ == "TLPMarking"]
        )
        == 1
    )
    ## Total 23 entities
    assert len(entities) == 23  # noqa: S101

    ## Sender feeds from_, recipients feed to_, cc feeds cc_.
    ## Header from/to addresses stay additional observables.
    message = next(entity for entity in entities if isinstance(entity, EmailMessage))
    assert message.from_ is not None  # noqa: S101
    assert message.from_.value == _DEFAULT_SENDER  # noqa: S101
    to_values = [address.value for address in message.to_ or []]
    cc_values = [address.value for address in message.cc_ or []]
    assert to_values == _DEFAULT_RECIPIENTS  # noqa: S101
    assert cc_values == _DEFAULT_CC_ADDRESSES  # noqa: S101
    _assert_address_values_and_relationship_sources(
        entities,
        _DEFAULT_OBSERVED_ADDRESS_VALUES,
    )
    stix_message = message.to_stix2_object()
    to_ref_ids = [address.id for address in message.to_ or []]
    cc_ref_ids = [address.id for address in message.cc_ or []]
    assert stix_message["from_ref"] == message.from_.id  # noqa: S101
    assert stix_message["sender_ref"] == message.from_.id  # noqa: S101
    assert stix_message["to_refs"] == to_ref_ids  # noqa: S101
    assert stix_message["cc_refs"] == cc_ref_ids  # noqa: S101
    header_ids = {
        address.id
        for address in _email_addresses(entities)
        if address.value in set(_DEFAULT_FROM_ADDRESSES + _DEFAULT_TO_ADDRESSES)
    }
    assert message.from_.id not in header_ids  # noqa: S101
    assert header_ids.isdisjoint(stix_message["to_refs"])  # noqa: S101
    assert header_ids.isdisjoint(stix_message["cc_refs"])  # noqa: S101

    ## Than can all be converted to stix object
    # all stix2 lib object
    _assert_entities_serialize_without_dangling_references(entities)


@pytest.mark.parametrize(
    "field_name",
    [
        "sender_address",
        "recipients",
        "from_addresses",
        "to_addresses",
        "cc_addresses",
    ],
)
@pytest.mark.parametrize("invalid_value", _INVALID_ADDRESS_VALUES)
def test_invalid_message_address_is_omitted(field_name: str, invalid_value: str):
    """Omit one invalid address without dropping the message or unrelated addresses."""
    # Given a message whose targeted address field is invalid
    field_value: Any = (
        invalid_value if field_name == "sender_address" else [invalid_value]
    )
    adapter = DummyMessageEventAdapter(**{field_name: field_value})
    # When running the processor on the adapter
    processor = IncidentProcessor(tlp_marking_name="white")
    entities = processor.run_on_event(adapter)
    # Then the invalid value is absent and every other valid address remains
    message = _assert_message_incident_bundle(entities)
    _assert_address_values_and_relationship_sources(
        entities, _expected_addresses_without(field_name)
    )
    observed_values = [address.value for address in _email_addresses(entities)]
    assert invalid_value not in observed_values  # noqa: S101
    if field_name == "sender_address":
        assert message.from_ is None  # noqa: S101
    else:
        assert message.from_ is not None  # noqa: S101
        assert message.from_.value == _DEFAULT_SENDER  # noqa: S101
    if field_name == "recipients":
        assert message.to_ == []  # noqa: S101
    else:
        to_values = [address.value for address in message.to_ or []]
        assert to_values == _DEFAULT_RECIPIENTS  # noqa: S101
    if field_name == "cc_addresses":
        assert message.cc_ == []  # noqa: S101
    else:
        cc_values = [address.value for address in message.cc_ or []]
        assert cc_values == _DEFAULT_CC_ADDRESSES  # noqa: S101
    _assert_entities_serialize_without_dangling_references(entities)


def test_mixed_valid_and_invalid_addresses_keep_order_and_duplicates():
    """Keep valid addresses that follow invalid ones, including duplicates, in order."""
    # Given a message mixing invalid, valid, and repeated addresses
    adapter = DummyMessageEventAdapter(
        sender_address=_DEFAULT_SENDER,
        from_addresses=[
            "info@[e051.Bunnings.com]",
            "from@example.com",
            "from@example.com",
        ],
        to_addresses=["", "to@example.com", "not-an-email"],
        recipients=[
            "not-an-email",
            "first@example.com",
            "   ",
            "dup@example.com",
            "dup@example.com",
        ],
        cc_addresses=[
            "cc@example.com",
            "info@[e051.Bunnings.com]",
            "later@example.com",
        ],
    )
    expected_values = [
        _DEFAULT_SENDER,
        "from@example.com",
        "from@example.com",
        "to@example.com",
        "first@example.com",
        "dup@example.com",
        "dup@example.com",
        "cc@example.com",
        "later@example.com",
    ]
    # When running the processor on the adapter
    processor = IncidentProcessor(tlp_marking_name="white")
    entities = processor.run_on_event(adapter)
    # Then surviving addresses and relationship sources keep input order and duplicates
    message = _assert_message_incident_bundle(entities)
    _assert_address_values_and_relationship_sources(entities, expected_values)
    assert message.from_ is not None  # noqa: S101
    assert message.from_.value == _DEFAULT_SENDER  # noqa: S101
    to_values = [address.value for address in message.to_ or []]
    cc_values = [address.value for address in message.cc_ or []]
    expected_to = ["first@example.com", "dup@example.com", "dup@example.com"]
    expected_cc = ["cc@example.com", "later@example.com"]
    assert to_values == expected_to  # noqa: S101
    assert cc_values == expected_cc  # noqa: S101
    _assert_entities_serialize_without_dangling_references(entities)


def test_invalid_sender_serializes_message_without_sender_refs():
    """Drop an invalid sender while keeping recipient, cc, and incident links."""
    # Given an invalid sender and valid recipient and cc addresses
    adapter = DummyMessageEventAdapter(
        sender_address="info@[e051.Bunnings.com]",
        recipients=["recipient1@example.com", "recipient2@example.com"],
        cc_addresses=["cc_address1@example.com"],
        from_addresses=["from_address1@example.com"],
        to_addresses=["to_address1@example.com"],
    )
    # When running the processor on the adapter
    processor = IncidentProcessor(tlp_marking_name="white")
    entities = processor.run_on_event(adapter)
    # Then the message has no from/sender ref and keeps to, cc, and the incident link
    message = _assert_message_incident_bundle(entities)
    assert message.from_ is None  # noqa: S101
    stix_message = message.to_stix2_object()
    assert stix_message.get("from_ref") is None  # noqa: S101
    assert stix_message.get("sender_ref") is None  # noqa: S101
    to_values = [address.value for address in message.to_ or []]
    cc_values = [address.value for address in message.cc_ or []]
    to_ref_ids = [address.id for address in message.to_ or []]
    cc_ref_ids = [address.id for address in message.cc_ or []]
    expected_to = ["recipient1@example.com", "recipient2@example.com"]
    expected_cc = ["cc_address1@example.com"]
    assert to_values == expected_to  # noqa: S101
    assert cc_values == expected_cc  # noqa: S101
    assert stix_message["to_refs"] == to_ref_ids  # noqa: S101
    assert stix_message["cc_refs"] == cc_ref_ids  # noqa: S101
    _assert_address_values_and_relationship_sources(
        entities,
        [
            "from_address1@example.com",
            "to_address1@example.com",
            "recipient1@example.com",
            "recipient2@example.com",
            "cc_address1@example.com",
        ],
    )
    _assert_entities_serialize_without_dangling_references(entities)


@pytest.mark.parametrize(
    "adapter_kwargs, expected_values",
    [
        pytest.param(
            {
                "sender_address": "",
                "recipients": ["not-an-email"],
                "from_addresses": ["   "],
                "to_addresses": ["info@[e051.Bunnings.com]"],
                "cc_addresses": ["missing-at"],
            },
            [],
            id="all-addresses-invalid",
        ),
        pytest.param(
            {
                "sender_address": "info@[e051.Bunnings.com]",
                "recipients": None,
                "from_addresses": None,
                "to_addresses": None,
                "cc_addresses": None,
            },
            [],
            id="optional-address-lists-none",
        ),
        pytest.param(
            {
                "sender_address": "   ",
                "recipients": [],
                "from_addresses": [],
                "to_addresses": [],
                "cc_addresses": [],
            },
            [],
            id="empty-address-lists",
        ),
        pytest.param(
            {
                "sender_address": _DEFAULT_SENDER,
                "recipients": None,
                "from_addresses": None,
                "to_addresses": None,
                "cc_addresses": None,
            },
            [_DEFAULT_SENDER],
            id="optional-address-lists-none-valid-sender",
        ),
        pytest.param(
            {
                "sender_address": _DEFAULT_SENDER,
                "recipients": [],
                "from_addresses": [],
                "to_addresses": [],
                "cc_addresses": [],
            },
            [_DEFAULT_SENDER],
            id="empty-address-lists-valid-sender",
        ),
    ],
)
def test_message_without_usable_addresses_still_emits_incident(
    adapter_kwargs: dict[str, Any], expected_values: list[str]
):
    """Emit the incident and message when no address, or only the sender, can be kept."""
    # Given a message with no usable list addresses
    adapter = DummyMessageEventAdapter(**adapter_kwargs)
    # When running the processor on the adapter
    processor = IncidentProcessor(tlp_marking_name="white")
    entities = processor.run_on_event(adapter)
    # Then the incident bundle remains and every serialized reference resolves
    message = _assert_message_incident_bundle(entities)
    _assert_address_values_and_relationship_sources(entities, expected_values)
    if expected_values:
        assert message.from_ is not None  # noqa: S101
        assert message.from_.value == expected_values[0]  # noqa: S101
    else:
        assert message.from_ is None  # noqa: S101
    assert message.to_ == []  # noqa: S101
    assert message.cc_ == []  # noqa: S101
    _assert_entities_serialize_without_dangling_references(entities)


def test_malformed_message_does_not_block_later_valid_message():
    """A skipped invalid address must not prevent the next message on the same processor."""
    # Given one processor and a malformed message followed by a valid message
    processor = IncidentProcessor(tlp_marking_name="white")
    malformed = DummyMessageEventAdapter(
        sender_address="info@[e051.Bunnings.com]",
        recipients=["not-an-email", "kept@example.com"],
        from_addresses=[""],
        to_addresses=["   "],
        cc_addresses=None,
    )
    # When both messages are processed in order
    malformed_entities = processor.run_on_event(malformed)
    valid_entities = processor.run_on_event(DummyMessageEventAdapter())
    # Then the first message keeps its valid recipient and the second is unchanged
    malformed_message = _assert_message_incident_bundle(malformed_entities)
    assert malformed_message.from_ is None  # noqa: S101
    _assert_address_values_and_relationship_sources(
        malformed_entities, ["kept@example.com"]
    )
    _assert_entities_serialize_without_dangling_references(malformed_entities)
    assert len(valid_entities) == 23  # noqa: S101
    valid_message = _assert_message_incident_bundle(valid_entities)
    assert valid_message.from_ is not None  # noqa: S101
    assert valid_message.from_.value == _DEFAULT_SENDER  # noqa: S101
    _assert_address_values_and_relationship_sources(
        valid_entities, _DEFAULT_OBSERVED_ADDRESS_VALUES
    )
    _assert_entities_serialize_without_dangling_references(valid_entities)


def test_unrelated_invalid_message_field_is_not_swallowed():
    """Validation errors outside the address value must still propagate."""
    # Given a message with valid addresses and a non-address field that cannot validate
    adapter = DummyMessageEventAdapter(subject={"not": "a string"})
    processor = IncidentProcessor(tlp_marking_name="white")
    # When running the processor on the adapter
    with pytest.raises(ValidationError) as caught:
        processor.run_on_event(adapter)
    # Then the unrelated field error is raised
    error_locations = [error["loc"] for error in caught.value.errors()]
    assert ("subject",) in error_locations  # noqa: S101

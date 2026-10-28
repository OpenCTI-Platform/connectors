# pragma: no cover
# type: ignore
import copy
import json
import logging
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk.connectors.internal_enrichment.base_enrichment_processor import (
    BaseEnrichmentProcessor,
)
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from connectors_sdk.connectors.internal_enrichment.exceptions import (
    EntityOutOfScopeError,
)
from connectors_sdk.connectors.internal_enrichment.internal_enrichment_connector import (
    InternalEnrichmentConnector,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import (
    AutonomousSystem,
    File,
    IPV4Address,
    OrganizationAuthor,
    Reference,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import HashAlgorithm, TLPLevel
from connectors_sdk.settings.base_settings import BaseInternalEnrichmentConnectorConfig
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError

PATCH_HELPER = "connectors_sdk.connectors.internal_enrichment.internal_enrichment_connector.OpenCTIConnectorHelper"

IP_ID = IPV4Address(value="1.2.3.4").id
OCTI_ID = "0b7e1c5a-3f2d-4e6a-9b8c-1d2e3f4a5b6c"
DOMAIN_ID = "domain-name--3c6b8a4e-1a52-5c1b-9b7e-3f3c3c7f4b6e"
INDICATOR_ID = "indicator--1f9e1b2e-1c3b-4b5e-8f4a-2b8f0f9e8d7c"
EXISTING_RELATED_ID = "x-opencti-text--0a2c6d1e-3f5b-5d7a-9c1e-4b6d8f0a2c4e"


# --- Example processors -------------------------------------------------------


class IPv4Processor(BaseEnrichmentProcessor):
    """Example processor rebuilding the enriched observable with SDK models."""

    handled_entity_types = frozenset({"IPv4-Addr"})

    def __init__(self, client: MagicMock) -> None:
        self.client = client

    def post_init(self) -> None:
        self.author = OrganizationAuthor(name="Example Source")
        self.tlp_marking = TLPMarking(level="clear")

    def collect(self, message: EnrichmentMessage) -> dict[str, Any] | None:
        return self.client.get_ip(message.stix_entity.value)

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        if not data:
            return []
        common = {"author": self.author, "markings": [self.tlp_marking]}
        # Same value, so same deterministic id: replaces the original entity
        ip = IPV4Address(value=message.stix_entity.value, score=data["score"], **common)
        asn = AutonomousSystem(number=data["asn"], **common)
        relationship = Relationship(type="belongs-to", source=ip, target=asn, **common)
        return [self.author, self.tlp_marking, ip, asn, relationship]


class DomainProcessor(BaseEnrichmentProcessor):
    """Example processor modifying a copy of the enriched entity."""

    handled_entity_types = frozenset({"Domain-Name", "Hostname"})

    def collect(self, message: EnrichmentMessage) -> dict[str, Any]:
        return {"score": 42}

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        entity = message.stix_entity.model_dump()
        entity["x_opencti_score"] = data["score"]
        return [entity]


class ShodanIndicatorProcessor(BaseEnrichmentProcessor):
    """Example processor filtering within a type by overriding can_process()."""

    handled_entity_types = frozenset({"Indicator"})

    def can_process(self, message: EnrichmentMessage) -> bool:
        return (
            super().can_process(message)
            and getattr(message.enrichment_entity, "pattern_type", None) == "shodan"
        )

    def collect(self, message: EnrichmentMessage) -> str:
        return "shodan"

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        return [{"type": "note", "id": "note--1", "content": data}]


class GenericIndicatorProcessor(BaseEnrichmentProcessor):
    """Example processor handling the indicators the Shodan processor does not handle."""

    handled_entity_types = frozenset({"Indicator"})

    def can_process(self, message: EnrichmentMessage) -> bool:
        return (
            super().can_process(message)
            and getattr(message.enrichment_entity, "pattern_type", None) != "shodan"
        )

    def collect(self, message: EnrichmentMessage) -> str:
        return "generic"

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        return [{"type": "note", "id": "note--2", "content": data}]


class AnyIndicatorProcessor(BaseEnrichmentProcessor):
    """Example processor overlapping with the Shodan processor: a code error."""

    handled_entity_types = frozenset({"Indicator"})

    def collect(self, message: EnrichmentMessage) -> str:
        return "any"

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        return [{"type": "note", "id": "note--4", "content": data}]


class ChangingProcessor(BaseEnrichmentProcessor):
    """Example processor changing the message, then failing."""

    handled_entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> Any:
        message.stix_objects[0]["object_marking_refs"].append("changed")
        raise DataRetrievalError("source unavailable")

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        return []


class InterruptedProcessor(BaseEnrichmentProcessor):
    handled_entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> Any:
        raise KeyboardInterrupt

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        return []


class FailingProcessor(BaseEnrichmentProcessor):
    handled_entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> Any:
        raise DataRetrievalError("source unavailable")

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        return []


class UnserializableProcessor(BaseEnrichmentProcessor):
    handled_entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> Any:
        return datetime.now(tz=timezone.utc)

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        # A plain dict holding a datetime cannot be serialized to JSON
        return [{"type": "note", "id": "note--3", "created": data}]


class FileHashesProcessor(BaseEnrichmentProcessor):
    """Example processor adding an MD5 to a file known by its SHA-256 only.

    The id of a file is computed from its MD5 first: rebuilt with an SDK model, the
    file would get another id. Modifying a copy of the entity keeps its id.
    """

    handled_entity_types = frozenset({"StixFile"})

    def collect(self, message: EnrichmentMessage) -> dict[str, str]:
        return {"md5": "b" * 32}

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        file = message.stix_entity.model_dump()
        file["hashes"]["MD5"] = data["md5"]
        asn = AutonomousSystem(number=64500)
        relationship = Relationship(
            type="related-to", source=Reference(id=message.stix_entity.id), target=asn
        )
        return [file, asn, relationship]


class LabelProcessor(BaseEnrichmentProcessor):
    """Example processor adding a label to the enriched IP with an SDK model."""

    handled_entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> list[str]:
        return ["vpn"]

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        return [IPV4Address(value=message.stix_entity.value, labels=data)]


class ReferenceProcessor(BaseEnrichmentProcessor):
    """Example processor linking new objects to the entity through a Reference."""

    handled_entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> int:
        return 64500

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        entity = Reference(id=message.stix_entity.id)
        asn = AutonomousSystem(number=data)
        relationship = Relationship(type="belongs-to", source=entity, target=asn)
        return [entity, asn, relationship]


# --- Helpers ------------------------------------------------------------------


def _make_settings(scope: list[str], max_tlp="TLP:AMBER") -> MagicMock:
    settings = MagicMock()
    settings.connector = BaseInternalEnrichmentConnectorConfig(
        id="connector--uid",
        name="Test Enrichment",
        scope=scope,
        max_tlp=max_tlp,
    )
    settings.to_helper_config.return_value = {"connector": {"name": "Test"}}
    return settings


def _processor_entity_types(processors: list[BaseEnrichmentProcessor]) -> list[str]:
    return [
        entity_type
        for processor in processors
        for entity_type in processor.handled_entity_types
    ]


def _make_helper(playbook: bool = False) -> MagicMock:
    helper = MagicMock()
    helper.playbook = {"playbook_id": "playbook--1"} if playbook else None
    helper.stix2_create_bundle.side_effect = OpenCTIConnectorHelper.stix2_create_bundle
    helper.send_stix2_bundle.return_value = ["bundle"]
    return helper


def _make_data(
    entity_type: str = "IPv4-Addr",
    stix_entity: dict | None = None,
    tlp: str | None = None,
    playbook: bool = False,
    **enrichment_entity_fields: Any,
) -> dict[str, Any]:
    stix_entity = stix_entity or {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": IP_ID,
        "value": "1.2.3.4",
        "object_marking_refs": ["marking-definition--original"],
    }
    related = {"type": "x-opencti-text", "id": EXISTING_RELATED_ID, "value": "t"}
    object_marking = (
        [{"definition_type": "TLP", "definition": tlp}] if tlp is not None else []
    )
    data = {
        "entity_id": stix_entity["id"],
        "enrichment_entity": {
            "id": OCTI_ID,
            "entity_type": entity_type,
            "objectMarking": object_marking,
            **enrichment_entity_fields,
        },
        # As sent by the platform in manual/auto mode: not the object inside stix_objects
        "stix_entity": stix_entity,
        "stix_objects": [dict(stix_entity), related],
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
        data["entity_type"] = entity_type
    return data


def _make_connector(
    helper: MagicMock,
    processors: list[BaseEnrichmentProcessor],
    settings: MagicMock | None = None,
) -> InternalEnrichmentConnector:
    """Build a connector whose scope is, by default, every type its processors declare."""
    connector = InternalEnrichmentConnector(
        settings=settings or _make_settings(scope=_processor_entity_types(processors)),
        enrichment_processors=processors,
    )
    with patch(PATCH_HELPER, return_value=helper):
        connector._init_dependencies()
    return connector


def _sent_objects(helper: MagicMock, call_index: int = 0) -> list[dict[str, Any]]:
    bundle = helper.send_stix2_bundle.call_args_list[call_index].args[0]
    return json.loads(bundle)["objects"]


def _sent_by_id(helper: MagicMock) -> dict[str, dict[str, Any]]:
    return {obj["id"]: obj for obj in _sent_objects(helper)}


def _logs(caplog: pytest.LogCaptureFixture, level: int) -> list[tuple[str, Any]]:
    """The (message, meta) of the records logged at `level`."""
    return [
        (record.getMessage(), getattr(record, "attributes", None))
        for record in caplog.records
        if record.levelno == level
    ]


def _ip_client(response: dict | None = None) -> MagicMock:
    client = MagicMock()
    client.get_ip.return_value = response
    return client


# --- Tests --------------------------------------------------------------------


class TestInit:
    def test_init(self):
        settings = _make_settings(scope=["Domain-Name"], max_tlp=TLPLevel.GREEN)
        processor = DomainProcessor()

        connector = InternalEnrichmentConnector(
            settings=settings, enrichment_processors=[processor]
        )

        assert connector.settings is settings
        assert connector.enrichment_processors == [processor]
        assert connector._enabled_entity_types == ["Domain-Name"]
        assert connector._max_entity_tlp is TLPLevel.GREEN

    def test_raises_when_connector_config_is_not_an_enrichment_config(self):
        settings = MagicMock()

        with pytest.raises(TypeError, match="BaseInternalEnrichmentConnectorConfig"):
            InternalEnrichmentConnector(
                settings=settings, enrichment_processors=[DomainProcessor()]
            )

    def test_raises_without_processors(self):
        with pytest.raises(ValueError, match="At least one BaseEnrichmentProcessor"):
            InternalEnrichmentConnector(
                settings=_make_settings(scope=["IPv4-Addr"]), enrichment_processors=[]
            )

    def test_raises_when_a_scope_type_is_declared_by_no_processor(self):
        with pytest.raises(
            ValueError,
            match="No processor declares the entity type Url of connector.scope",
        ):
            InternalEnrichmentConnector(
                settings=_make_settings(scope=["domain-name", "Url"]),
                enrichment_processors=[DomainProcessor()],
            )

    def test_accepts_processors_declaring_the_same_entity_type(self):
        connector = InternalEnrichmentConnector(
            settings=_make_settings(scope=["Indicator"]),
            enrichment_processors=[
                GenericIndicatorProcessor(),
                ShodanIndicatorProcessor(),
            ],
        )

        assert len(connector.enrichment_processors) == 2


class TestInitDependencies:
    def test_creates_a_playbook_compatible_helper(self):
        connector = InternalEnrichmentConnector(
            settings=_make_settings(scope=["Domain-Name"]),
            enrichment_processors=[DomainProcessor()],
        )

        with patch(PATCH_HELPER, return_value=_make_helper()) as helper_cls:
            connector._init_dependencies()

        helper_cls.assert_called_once_with(
            config={"connector": {"name": "Test"}}, playbook_compatible=True
        )
        assert connector.logger is not None

    def test_injects_dependencies_and_calls_post_init(self):
        settings = _make_settings(scope=["IPv4-Addr"])
        processor = IPv4Processor(client=_ip_client())

        connector = _make_connector(_make_helper(), [processor], settings=settings)

        assert processor.settings is settings
        assert processor.message_manager is connector._message_manager
        assert processor.logger is not None
        assert processor.author.name == "Example Source"


class TestStart:
    def test_start_listens_with_the_callback(self):
        helper = _make_helper()
        connector = InternalEnrichmentConnector(
            settings=_make_settings(scope=["Domain-Name"]),
            enrichment_processors=[DomainProcessor()],
        )

        with patch(PATCH_HELPER, return_value=helper):
            connector.start()

        helper.listen.assert_called_once_with(message_callback=connector.callback)


class TestIsEntityInScope:
    @pytest.mark.parametrize("entity_type", ["IPv4-Addr", "ipv4-addr", "IPV4-ADDR"])
    def test_is_case_insensitive(self, entity_type):
        assert InternalEnrichmentConnector.is_entity_in_scope(
            entity_type, ["Domain-Name", "IPv4-Addr"]
        )

    def test_refuses_other_types(self):
        assert not InternalEnrichmentConnector.is_entity_in_scope(
            "Url", ["Domain-Name", "IPv4-Addr"]
        )


class TestIsEntityTlpAllowed:
    @pytest.mark.parametrize(
        "tlp_levels",
        [
            [],
            ["TLP:CLEAR"],
            ["TLP:WHITE"],
            ["TLP:GREEN", "TLP:AMBER"],
            ["amber"],
            ["Tlp:Green", "amber"],
        ],
    )
    def test_allows_entities_up_to_max_tlp(self, tlp_levels):
        assert InternalEnrichmentConnector.is_entity_tlp_allowed(
            tlp_levels, TLPLevel.AMBER
        )

    @pytest.mark.parametrize(
        "tlp_levels",
        [["TLP:AMBER+STRICT"], ["TLP:GREEN", "TLP:RED"], ["TLP:EX:CHEMICAL"]],
        ids=["above", "one_above", "unknown"],
    )
    def test_refuses_entities_above_max_tlp(self, tlp_levels):
        assert not InternalEnrichmentConnector.is_entity_tlp_allowed(
            tlp_levels, TLPLevel.AMBER
        )

    @pytest.mark.parametrize("max_entity_tlp", ["TLP:AMBER", "amber", "Tlp:Amber"])
    def test_accepts_a_max_tlp_given_as_a_string(self, max_entity_tlp):
        is_entity_tlp_allowed = InternalEnrichmentConnector.is_entity_tlp_allowed

        assert is_entity_tlp_allowed(["TLP:AMBER"], max_entity_tlp)
        assert not is_entity_tlp_allowed(["TLP:AMBER+STRICT"], max_entity_tlp)

    @pytest.mark.parametrize("max_entity_tlp", ["TLP:PURPLE", ""])
    def test_raises_on_an_invalid_max_tlp(self, max_entity_tlp):
        with pytest.raises(ValueError, match="is not a valid TLPLevel"):
            InternalEnrichmentConnector.is_entity_tlp_allowed([], max_entity_tlp)


class TestCallbackEnrichment:
    def test_sends_original_objects_and_new_objects(self):
        helper = _make_helper()
        connector = _make_connector(
            helper, [IPv4Processor(client=_ip_client({"score": 80, "asn": 13335}))]
        )

        result = connector.callback(_make_data())

        assert result == "Entity enriched with 5 objects"
        helper.send_stix2_bundle.assert_called_once()
        assert helper.send_stix2_bundle.call_args.kwargs == {
            "cleanup_inconsistent_bundle": True
        }
        sent = _sent_by_id(helper)
        assert EXISTING_RELATED_ID in sent
        assert {obj["type"] for obj in sent.values()} == {
            "ipv4-addr",
            "x-opencti-text",
            "identity",
            "marking-definition",
            "autonomous-system",
            "relationship",
        }

    def test_replaces_the_entity_with_an_object_with_the_same_id(self):
        helper = _make_helper()
        connector = _make_connector(helper, [LabelProcessor()])

        connector.callback(_make_data())

        sent = _sent_objects(helper)
        entities = [obj for obj in sent if obj["id"] == IP_ID]
        # Replaced in place: OpenCTI merges it with the entity it holds
        assert sent[0]["id"] == IP_ID
        assert len(entities) == 1
        assert entities[0]["x_opencti_labels"] == ["vpn"]
        assert "object_marking_refs" not in entities[0]

    def test_keeps_the_id_of_a_copy_of_the_entity_given_a_new_hash(self):
        helper = _make_helper()
        connector = _make_connector(helper, [FileHashesProcessor()])
        sha256 = "a" * 64
        file_id = File(hashes={HashAlgorithm.SHA256: sha256}).id
        entity = {"type": "file", "id": file_id, "hashes": {"SHA-256": sha256}}

        connector.callback(_make_data(entity_type="StixFile", stix_entity=entity))

        sent = _sent_objects(helper)
        [file] = [obj for obj in sent if obj["type"] == "file"]
        assert file["id"] == file_id
        assert file["hashes"] == {"SHA-256": sha256, "MD5": "b" * 32}
        [relationship] = [obj for obj in sent if obj["type"] == "relationship"]
        assert relationship["source_ref"] == file_id

    def test_ignores_references_and_links_objects_to_the_entity_through_them(self):
        helper = _make_helper()
        connector = _make_connector(helper, [ReferenceProcessor()])

        result = connector.callback(_make_data())

        assert result == "Entity enriched with 3 objects"
        sent = _sent_objects(helper)
        assert [obj["id"] for obj in sent].count(IP_ID) == 1
        [relationship] = [obj for obj in sent if obj["type"] == "relationship"]
        assert relationship["source_ref"] == IP_ID

    def test_adds_the_entity_when_it_is_not_in_the_original_objects(self):
        helper = _make_helper()
        connector = _make_connector(helper, [LabelProcessor()])
        data = _make_data()
        data["stix_objects"] = [
            obj for obj in data["stix_objects"] if obj["id"] != IP_ID
        ]

        connector.callback(data)

        sent = _sent_by_id(helper)[IP_ID]
        assert sent["x_opencti_labels"] == ["vpn"]

    def test_modified_copy_of_the_entity_reaches_the_bundle(self):
        helper = _make_helper()
        connector = _make_connector(helper, [DomainProcessor()])
        domain = {"type": "domain-name", "id": DOMAIN_ID, "value": "example.com"}

        connector.callback(_make_data(entity_type="Domain-Name", stix_entity=domain))

        sent = _sent_by_id(helper)
        assert sent[DOMAIN_ID]["x_opencti_score"] == 42
        assert "x_opencti_score" not in domain

    def test_scope_is_case_insensitive(self):
        helper = _make_helper()
        connector = _make_connector(
            helper,
            [IPv4Processor(client=_ip_client({"score": 80, "asn": 13335}))],
            settings=_make_settings(scope=["ipv4-addr"]),
        )

        result = connector.callback(_make_data())

        assert result == "Entity enriched with 5 objects"

    @pytest.mark.parametrize(
        "pattern_type, expected_note", [("shodan", "note--1"), ("stix", "note--2")]
    )
    @pytest.mark.parametrize("reverse_order", [False, True])
    def test_uses_the_only_processor_able_to_process_the_entity(
        self, pattern_type, expected_note, reverse_order
    ):
        helper = _make_helper()
        processors = [ShodanIndicatorProcessor(), GenericIndicatorProcessor()]
        connector = _make_connector(
            helper, processors[::-1] if reverse_order else processors
        )
        indicator = {"type": "indicator", "id": INDICATOR_ID, "pattern": "p"}

        connector.callback(
            _make_data(
                entity_type="Indicator",
                stix_entity=indicator,
                pattern_type=pattern_type,
            )
        )

        sent = _sent_by_id(helper)
        [other_note] = {"note--1", "note--2"} - {expected_note}
        assert expected_note in sent
        assert other_note not in sent

    @pytest.mark.parametrize("tlp", [None, "TLP:CLEAR", "TLP:AMBER"])
    def test_enriches_entities_up_to_max_tlp(self, tlp):
        helper = _make_helper()
        connector = _make_connector(helper, [DomainProcessor()])
        domain = {"type": "domain-name", "id": DOMAIN_ID, "value": "example.com"}

        result = connector.callback(
            _make_data(entity_type="Domain-Name", stix_entity=domain, tlp=tlp)
        )

        assert result == "Entity enriched with 1 objects"

    def test_compares_tlp_with_a_max_tlp_given_as_a_level(self):
        helper = _make_helper()
        connector = _make_connector(
            helper,
            [DomainProcessor()],
            settings=_make_settings(
                scope=["Domain-Name"], max_tlp=TLPLevel.AMBER_STRICT
            ),
        )
        domain = {"type": "domain-name", "id": DOMAIN_ID, "value": "example.com"}

        result = connector.callback(
            _make_data(
                entity_type="Domain-Name", stix_entity=domain, tlp="TLP:AMBER+STRICT"
            )
        )

        assert result == "Entity enriched with 1 objects"

    def test_enriches_in_a_playbook(self):
        helper = _make_helper(playbook=True)
        connector = _make_connector(
            helper, [IPv4Processor(client=_ip_client({"score": 80, "asn": 13335}))]
        )

        connector.callback(_make_data(playbook=True))

        helper.send_stix2_bundle.assert_called_once()
        assert _sent_by_id(helper)[IP_ID]["x_opencti_score"] == 80


SKIP_CASES = [
    pytest.param(
        {"entity_type": "Indicator", "pattern_type": "stix"},
        "No processor can process this entity",
        id="no_processor",
    ),
    pytest.param(
        {"tlp": "TLP:RED"}, "Entity TLP is not allowed (max TLP: amber)", id="tlp"
    ),
    pytest.param({}, "No enrichment data found", id="no_data"),
]
# Outside playbooks, an entity out of scope is an error (see TestCallbackErrors)
PLAYBOOK_SKIP_CASES = [
    pytest.param(
        {"entity_type": "Url"}, "Entity type Url is out of scope", id="out_of_scope"
    ),
    *SKIP_CASES,
]


class TestCallbackSkips:
    @pytest.mark.parametrize("data_kwargs, expected_result", SKIP_CASES)
    def test_manual_skip_sends_nothing_and_completes_the_work(
        self, data_kwargs, expected_result
    ):
        helper = _make_helper()
        connector = _make_connector(
            helper, [IPv4Processor(client=_ip_client(None)), ShodanIndicatorProcessor()]
        )

        result = connector.callback(_make_data(**data_kwargs))

        assert result == expected_result
        helper.send_stix2_bundle.assert_not_called()

    @pytest.mark.parametrize("data_kwargs, expected_result", PLAYBOOK_SKIP_CASES)
    def test_playbook_skip_sends_the_original_bundle_once(
        self, data_kwargs, expected_result
    ):
        helper = _make_helper(playbook=True)
        connector = _make_connector(
            helper, [IPv4Processor(client=_ip_client(None)), ShodanIndicatorProcessor()]
        )
        data = _make_data(playbook=True, **data_kwargs)
        original = [dict(obj) for obj in data["stix_objects"]]

        result = connector.callback(data)

        assert result == expected_result
        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_tlp_refusal_happens_before_calling_the_source(self, caplog):
        caplog.set_level(logging.WARNING)
        helper = _make_helper()
        client = _ip_client({"score": 80, "asn": 13335})
        connector = _make_connector(helper, [IPv4Processor(client=client)])

        connector.callback(_make_data(tlp="TLP:AMBER+STRICT"))

        client.get_ip.assert_not_called()
        assert _logs(caplog, logging.WARNING) == [
            (
                "Entity TLP is not allowed by the connector max TLP, skipping",
                {
                    "octi_id": OCTI_ID,
                    "octi_entity_type": "IPv4-Addr",
                    "from_playbook": False,
                    "tlp_levels": ["TLP:AMBER+STRICT"],
                    "max_entity_tlp": "amber",
                },
            )
        ]

    def test_out_of_scope_is_checked_before_tlp(self, caplog):
        caplog.set_level(logging.INFO)
        helper = _make_helper(playbook=True)
        connector = _make_connector(helper, [DomainProcessor()])

        result = connector.callback(
            _make_data(entity_type="Url", tlp="TLP:RED", playbook=True)
        )

        assert result == "Entity type Url is out of scope"
        assert _logs(caplog, logging.WARNING) == []
        assert (
            "Entity type is out of the connector scope",
            {"octi_id": OCTI_ID, "octi_entity_type": "Url", "from_playbook": True},
        ) in _logs(caplog, logging.INFO)

    def test_tlp_is_checked_before_any_processor_sees_the_entity(self, caplog):
        caplog.set_level(logging.WARNING)
        helper = _make_helper()
        processor = ShodanIndicatorProcessor()
        connector = _make_connector(helper, [processor])
        # can_process() is connector code, which may call the source
        processor.can_process = MagicMock(wraps=processor.can_process)

        result = connector.callback(
            _make_data(entity_type="Indicator", pattern_type="stix", tlp="TLP:RED")
        )

        assert result == "Entity TLP is not allowed (max TLP: amber)"
        processor.can_process.assert_not_called()
        assert [message for message, _ in _logs(caplog, logging.WARNING)] == [
            "Entity TLP is not allowed by the connector max TLP, skipping"
        ]

    def test_logs_when_no_processor_can_process_the_entity(self, caplog):
        caplog.set_level(logging.WARNING)
        helper = _make_helper()
        connector = _make_connector(helper, [ShodanIndicatorProcessor()])

        connector.callback(_make_data(entity_type="Indicator", pattern_type="stix"))

        assert _logs(caplog, logging.WARNING) == [
            (
                "No processor can process the entity, skipping",
                {
                    "octi_id": OCTI_ID,
                    "octi_entity_type": "Indicator",
                    "from_playbook": False,
                },
            )
        ]


class TestCallbackErrors:
    @pytest.mark.parametrize("playbook", [False, True])
    def test_invalid_message_is_logged_and_reraised_without_sending(
        self, playbook, caplog
    ):
        helper = _make_helper(playbook=playbook)
        connector = _make_connector(helper, [DomainProcessor()])
        data = _make_data(playbook=playbook)
        del data["enrichment_entity"]

        with pytest.raises(ValidationError):
            connector.callback(data)

        helper.send_stix2_bundle.assert_not_called()
        assert _logs(caplog, logging.ERROR) == [
            ("Invalid enrichment message", {"entity_id": IP_ID})
        ]

    def test_manual_out_of_scope_entity_is_an_error(self, caplog):
        helper = _make_helper()
        client = _ip_client({"score": 80, "asn": 13335})
        connector = _make_connector(helper, [IPv4Processor(client=client)])

        with pytest.raises(
            EntityOutOfScopeError, match="Entity type Url is out of scope"
        ):
            connector.callback(_make_data(entity_type="Url", tlp="TLP:RED"))

        client.get_ip.assert_not_called()
        helper.send_stix2_bundle.assert_not_called()
        assert _logs(caplog, logging.ERROR) == [
            (
                "Enrichment failed",
                {
                    "octi_id": OCTI_ID,
                    "octi_entity_type": "Url",
                    "from_playbook": False,
                },
            )
        ]

    def test_manual_error_is_logged_and_reraised_without_sending(self, caplog):
        helper = _make_helper()
        connector = _make_connector(helper, [FailingProcessor()])

        with pytest.raises(DataRetrievalError, match="source unavailable"):
            connector.callback(_make_data())

        helper.send_stix2_bundle.assert_not_called()
        assert _logs(caplog, logging.ERROR) == [
            (
                "Enrichment failed",
                {
                    "octi_id": OCTI_ID,
                    "octi_entity_type": "IPv4-Addr",
                    "from_playbook": False,
                },
            )
        ]
        # The error text reaches the logs through the traceback
        [record] = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert str(record.exc_info[1]) == "source unavailable"

    def test_playbook_error_sends_the_original_bundle_then_reraises(self):
        helper = _make_helper(playbook=True)
        connector = _make_connector(helper, [FailingProcessor()])
        data = _make_data(playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        with pytest.raises(DataRetrievalError):
            connector.callback(data)

        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    @pytest.mark.parametrize("playbook", [False, True])
    def test_several_processors_able_to_process_the_entity_is_an_error(self, playbook):
        helper = _make_helper(playbook=playbook)
        connector = _make_connector(
            helper, [ShodanIndicatorProcessor(), AnyIndicatorProcessor()]
        )
        data = _make_data(entity_type="Indicator", playbook=playbook)
        data["enrichment_entity"]["pattern_type"] = "shodan"

        with pytest.raises(
            ValueError,
            match=r"Several processors can process the entity "
            r"\(ShodanIndicatorProcessor, AnyIndicatorProcessor\)",
        ):
            connector.callback(data)

        # Only the original bundle, in a playbook
        assert helper.send_stix2_bundle.call_count == (1 if playbook else 0)

    def test_playbook_send_failure_is_logged_then_the_original_bundle_is_sent(
        self, caplog
    ):
        helper = _make_helper(playbook=True)
        helper.send_stix2_bundle.side_effect = RuntimeError("queue down")
        connector = _make_connector(
            helper, [IPv4Processor(client=_ip_client({"score": 80, "asn": 13335}))]
        )

        with pytest.raises(RuntimeError, match="queue down"):
            connector.callback(_make_data(playbook=True))

        # A failed send does not count as sent: the original bundle is tried next
        assert helper.send_stix2_bundle.call_count == 2
        metadata = {
            "octi_id": OCTI_ID,
            "octi_entity_type": "IPv4-Addr",
            "from_playbook": True,
        }
        assert _logs(caplog, logging.ERROR) == [
            ("Enrichment failed", metadata),
            ("Failed to send the original bundle back", metadata),
        ]

    def test_manual_unserializable_objects_raise_without_sending(self):
        helper = _make_helper()
        connector = _make_connector(helper, [UnserializableProcessor()])

        with pytest.raises(TypeError, match="not JSON serializable"):
            connector.callback(_make_data())

        helper.send_stix2_bundle.assert_not_called()

    def test_playbook_unserializable_objects_send_the_original_bundle_once(self):
        helper = _make_helper(playbook=True)
        connector = _make_connector(helper, [UnserializableProcessor()])
        data = _make_data(playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        with pytest.raises(TypeError, match="not JSON serializable"):
            connector.callback(data)

        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_playbook_fallback_send_failure_is_logged_and_original_error_reraised(
        self, caplog
    ):
        helper = _make_helper(playbook=True)
        helper.send_stix2_bundle.side_effect = ConnectionError("API down")
        connector = _make_connector(helper, [FailingProcessor()])

        with pytest.raises(DataRetrievalError, match="source unavailable"):
            connector.callback(_make_data(playbook=True))

        assert _logs(caplog, logging.ERROR)[-1] == (
            "Failed to send the original bundle back",
            {
                "octi_id": OCTI_ID,
                "octi_entity_type": "IPv4-Addr",
                "from_playbook": True,
            },
        )

    def test_playbook_sends_the_original_bundle_as_received(self):
        helper = _make_helper(playbook=True)
        connector = _make_connector(helper, [ChangingProcessor()])
        data = _make_data(playbook=True)
        original = copy.deepcopy(data["stix_objects"])

        with pytest.raises(DataRetrievalError):
            connector.callback(data)

        assert _sent_objects(helper) == original

    def test_playbook_skip_logs_a_failure_to_send_the_original_bundle(self, caplog):
        helper = _make_helper(playbook=True)
        helper.send_stix2_bundle.side_effect = ConnectionError("API down")
        connector = _make_connector(helper, [IPv4Processor(client=_ip_client())])

        result = connector.callback(_make_data(tlp="TLP:RED", playbook=True))

        assert result == "Entity TLP is not allowed (max TLP: amber)"
        assert [message for message, _ in _logs(caplog, logging.ERROR)] == [
            "Failed to send the original bundle back"
        ]

    @pytest.mark.parametrize("playbook", [False, True])
    def test_keyboard_interrupt_stops_the_connector(self, playbook):
        helper = _make_helper(playbook=playbook)
        connector = _make_connector(helper, [InterruptedProcessor()])

        with pytest.raises(KeyboardInterrupt):
            connector.callback(_make_data(playbook=playbook))

        # In a playbook, the original bundle is still sent back
        assert helper.send_stix2_bundle.call_count == (1 if playbook else 0)

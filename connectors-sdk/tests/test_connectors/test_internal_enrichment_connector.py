# pragma: no cover
# type: ignore
import json
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
from connectors_sdk.connectors.internal_enrichment.internal_enrichment_connector import (
    InternalEnrichmentConnector,
)
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import (
    AutonomousSystem,
    IPV4Address,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from connectors_sdk.settings.base_settings import BaseInternalEnrichmentConnectorConfig
from pycti import OpenCTIConnectorHelper

PATCH_HELPER = "connectors_sdk.connectors.internal_enrichment.internal_enrichment_connector.OpenCTIConnectorHelper"

IP_ID = IPV4Address(value="1.2.3.4").id
DOMAIN_ID = "domain-name--3c6b8a4e-1a52-5c1b-9b7e-3f3c3c7f4b6e"
INDICATOR_ID = "indicator--1f9e1b2e-1c3b-4b5e-8f4a-2b8f0f9e8d7c"
EXISTING_RELATED_ID = "x-opencti-text--0a2c6d1e-3f5b-5d7a-9c1e-4b6d8f0a2c4e"


# --- Example processors -------------------------------------------------------


class IPv4Processor(BaseEnrichmentProcessor):
    """Example processor rebuilding the enriched observable with SDK models."""

    entity_types = frozenset({"IPv4-Addr"})

    def __init__(self, client: MagicMock) -> None:
        self.client = client

    def post_init(self) -> None:
        self.author = OrganizationAuthor(name="Example Source")
        self.tlp_marking = TLPMarking(level="clear")

    def collect(self, message: EnrichmentMessage) -> dict[str, Any] | None:
        return self.client.get_ip(message.stix_entity["value"])

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        if not data:
            return []
        common = {"author": self.author, "markings": [self.tlp_marking]}
        # Same value, so same deterministic id: replaces the original entity
        ip = IPV4Address(
            value=message.stix_entity["value"], score=data["score"], **common
        )
        asn = AutonomousSystem(number=data["asn"], **common)
        relationship = Relationship(type="belongs-to", source=ip, target=asn, **common)
        return [self.author, self.tlp_marking, ip, asn, relationship]


class DomainProcessor(BaseEnrichmentProcessor):
    """Example processor modifying a copy of the enriched entity."""

    entity_types = frozenset({"Domain-Name", "Hostname"})

    def collect(self, message: EnrichmentMessage) -> dict[str, Any]:
        return {"score": 42}

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        entity = message.entity_copy()
        entity["x_opencti_score"] = data["score"]
        return [entity]


class ShodanIndicatorProcessor(BaseEnrichmentProcessor):
    """Example processor filtering within a type by overriding supports()."""

    entity_types = frozenset({"Indicator"})

    def supports(self, message: EnrichmentMessage) -> bool:
        return (
            super().supports(message)
            and message.enrichment_entity.get("pattern_type") == "shodan"
        )

    def collect(self, message: EnrichmentMessage) -> str:
        return "shodan"

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        return [{"type": "note", "id": "note--1", "content": data}]


class GenericIndicatorProcessor(BaseEnrichmentProcessor):
    entity_types = frozenset({"Indicator"})

    def collect(self, message: EnrichmentMessage) -> str:
        return "generic"

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        return [{"type": "note", "id": "note--2", "content": data}]


class FailingProcessor(BaseEnrichmentProcessor):
    entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> Any:
        raise DataRetrievalError("source unavailable")

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        return []


class UnserializableProcessor(BaseEnrichmentProcessor):
    entity_types = frozenset({"IPv4-Addr"})

    def collect(self, message: EnrichmentMessage) -> Any:
        return datetime.now(tz=timezone.utc)

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        # A plain dict holding a datetime cannot be serialized to JSON
        return [{"type": "note", "id": "note--3", "created": data}]


class EmptyTypesProcessor(BaseEnrichmentProcessor):
    entity_types = frozenset()

    def collect(self, message: EnrichmentMessage) -> Any:
        return None

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        return []


# --- Helpers ------------------------------------------------------------------


def _make_settings(scope=None, max_tlp="TLP:AMBER") -> MagicMock:
    settings = MagicMock()
    settings.connector = BaseInternalEnrichmentConnectorConfig(
        id="connector--uid",
        name="Test Enrichment",
        scope=scope or ["IPv4-Addr", "Domain-Name", "Hostname", "Indicator"],
        max_tlp=max_tlp,
    )
    settings.to_helper_config.return_value = {"connector": {"name": "Test"}}
    return settings


def _make_helper(playbook: bool = False) -> MagicMock:
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.playbook = {"playbook_id": "playbook--1"} if playbook else None
    helper.check_max_tlp.side_effect = OpenCTIConnectorHelper.check_max_tlp
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
    connector = InternalEnrichmentConnector(
        settings=settings or _make_settings(), enrichment_processors=processors
    )
    with patch(PATCH_HELPER, return_value=helper):
        connector._init_dependencies()
    return connector


def _sent_objects(helper: MagicMock, call_index: int = 0) -> list[dict[str, Any]]:
    bundle = helper.send_stix2_bundle.call_args_list[call_index].args[0]
    return json.loads(bundle)["objects"]


def _sent_by_id(helper: MagicMock) -> dict[str, dict[str, Any]]:
    return {obj["id"]: obj for obj in _sent_objects(helper)}


def _ip_client(response: dict | None = None) -> MagicMock:
    client = MagicMock()
    client.get_ip.return_value = response
    return client


# --- Tests --------------------------------------------------------------------


class TestInit:
    def test_init(self):
        settings = _make_settings()
        processor = DomainProcessor()

        connector = InternalEnrichmentConnector(
            settings=settings, enrichment_processors=[processor]
        )

        assert connector.settings is settings
        assert connector.enrichment_processors == [processor]

    def test_raises_when_connector_config_is_not_an_enrichment_config(self):
        settings = MagicMock()

        with pytest.raises(TypeError, match="BaseInternalEnrichmentConnectorConfig"):
            InternalEnrichmentConnector(
                settings=settings, enrichment_processors=[DomainProcessor()]
            )

    def test_raises_without_processors(self):
        with pytest.raises(ValueError, match="At least one BaseEnrichmentProcessor"):
            InternalEnrichmentConnector(
                settings=_make_settings(), enrichment_processors=[]
            )

    def test_raises_when_a_processor_has_no_entity_types(self):
        with pytest.raises(ValueError, match="EmptyTypesProcessor.entity_types"):
            InternalEnrichmentConnector(
                settings=_make_settings(), enrichment_processors=[EmptyTypesProcessor()]
            )


class TestInitDependencies:
    def test_creates_a_playbook_compatible_helper(self):
        settings = _make_settings()
        connector = InternalEnrichmentConnector(
            settings=settings, enrichment_processors=[DomainProcessor()]
        )

        with patch(PATCH_HELPER, return_value=_make_helper()) as helper_cls:
            connector._init_dependencies()

        helper_cls.assert_called_once_with(
            config={"connector": {"name": "Test"}}, playbook_compatible=True
        )
        assert connector.logger is not None

    def test_injects_dependencies_and_calls_post_init(self):
        settings = _make_settings()
        processor = IPv4Processor(client=_ip_client())

        _make_connector(_make_helper(), [processor], settings=settings)

        assert processor.settings is settings
        assert processor.logger is not None
        assert processor.author.name == "Example Source"

    def test_warns_about_scope_types_without_processor(self):
        helper = _make_helper()

        _make_connector(
            helper,
            [DomainProcessor()],
            settings=_make_settings(scope=["domain-name", "Url"]),
        )

        helper.connector_logger.warning.assert_called_once_with(
            "[CONNECTOR] Scope entity type is not handled by any processor",
            {"entity_type": "Url"},
        )

    def test_warns_about_types_shadowed_by_an_earlier_processor(self):
        helper = _make_helper()

        _make_connector(
            helper,
            [GenericIndicatorProcessor(), ShodanIndicatorProcessor()],
            settings=_make_settings(scope=["Indicator"]),
        )

        helper.connector_logger.warning.assert_called_once_with(
            "[CONNECTOR] Entity type already claimed by an earlier processor, "
            "this processor will never receive it",
            {
                "entity_type": "Indicator",
                "processor": "ShodanIndicatorProcessor",
                "claimed_by": "GenericIndicatorProcessor",
            },
        )

    def test_does_not_warn_when_the_earlier_processor_overrides_supports(self):
        helper = _make_helper()

        _make_connector(
            helper,
            [ShodanIndicatorProcessor(), GenericIndicatorProcessor()],
            settings=_make_settings(scope=["Indicator"]),
        )

        helper.connector_logger.warning.assert_not_called()


class TestStart:
    def test_start_listens_with_the_callback(self):
        helper = _make_helper()
        connector = InternalEnrichmentConnector(
            settings=_make_settings(), enrichment_processors=[DomainProcessor()]
        )

        with patch(PATCH_HELPER, return_value=helper):
            connector.start()

        helper.listen.assert_called_once_with(message_callback=connector.callback)


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

    def test_replaces_the_enriched_entity_by_id(self):
        helper = _make_helper()
        connector = _make_connector(
            helper, [IPv4Processor(client=_ip_client({"score": 80, "asn": 13335}))]
        )

        connector.callback(_make_data())

        sent = _sent_objects(helper)
        entities = [obj for obj in sent if obj["id"] == IP_ID]
        assert len(entities) == 1
        assert entities[0]["x_opencti_score"] == 80
        # The original entity keeps its position at the start of the bundle
        assert sent[0]["id"] == IP_ID

    def test_entity_copy_modifications_reach_the_bundle(self):
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

    def test_uses_the_specific_processor_when_it_supports_the_entity(self):
        helper = _make_helper()
        connector = _make_connector(
            helper, [ShodanIndicatorProcessor(), GenericIndicatorProcessor()]
        )
        indicator = {"type": "indicator", "id": INDICATOR_ID, "pattern": "p"}

        connector.callback(
            _make_data(
                entity_type="Indicator", stix_entity=indicator, pattern_type="shodan"
            )
        )

        assert "note--1" in _sent_by_id(helper)

    def test_falls_back_to_the_next_processor_when_the_first_does_not_support_it(
        self,
    ):
        helper = _make_helper()
        connector = _make_connector(
            helper, [ShodanIndicatorProcessor(), GenericIndicatorProcessor()]
        )
        indicator = {"type": "indicator", "id": INDICATOR_ID, "pattern": "p"}

        connector.callback(
            _make_data(
                entity_type="Indicator", stix_entity=indicator, pattern_type="stix"
            )
        )

        assert "note--2" in _sent_by_id(helper)

    @pytest.mark.parametrize("tlp", [None, "TLP:CLEAR", "TLP:AMBER"])
    def test_enriches_entities_up_to_max_tlp(self, tlp):
        helper = _make_helper()
        connector = _make_connector(helper, [DomainProcessor()])
        domain = {"type": "domain-name", "id": DOMAIN_ID, "value": "example.com"}

        result = connector.callback(
            _make_data(entity_type="Domain-Name", stix_entity=domain, tlp=tlp)
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


class TestCallbackSkips:
    @pytest.mark.parametrize(
        "data_kwargs, expected_result",
        [
            ({"entity_type": "Url"}, "Entity type Url is out of scope"),
            (
                {"entity_type": "Indicator", "pattern_type": "stix"},
                "No processor supports this entity",
            ),
            ({"tlp": "TLP:RED"}, "Entity TLP is above max TLP (TLP:AMBER)"),
            ({}, "No enrichment data found"),
        ],
        ids=["out_of_scope", "no_processor", "tlp_too_high", "no_data"],
    )
    def test_manual_skip_sends_nothing_and_completes_the_work(
        self, data_kwargs, expected_result
    ):
        helper = _make_helper()
        client = _ip_client(None)
        connector = _make_connector(
            helper, [IPv4Processor(client=client), ShodanIndicatorProcessor()]
        )

        result = connector.callback(_make_data(**data_kwargs))

        assert result == expected_result
        helper.send_stix2_bundle.assert_not_called()

    @pytest.mark.parametrize(
        "data_kwargs",
        [
            {"entity_type": "Url"},
            {"entity_type": "Indicator", "pattern_type": "stix"},
            {"tlp": "TLP:RED"},
            {},
        ],
        ids=["out_of_scope", "no_processor", "tlp_too_high", "no_data"],
    )
    def test_playbook_skip_sends_the_original_bundle_once(self, data_kwargs):
        helper = _make_helper(playbook=True)
        connector = _make_connector(
            helper, [IPv4Processor(client=_ip_client(None)), ShodanIndicatorProcessor()]
        )
        data = _make_data(playbook=True, **data_kwargs)
        original = [dict(obj) for obj in data["stix_objects"]]

        connector.callback(data)

        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_tlp_refusal_happens_before_calling_the_source(self):
        helper = _make_helper()
        client = _ip_client({"score": 80, "asn": 13335})
        connector = _make_connector(
            helper,
            [IPv4Processor(client=client)],
            settings=_make_settings(scope=["IPv4-Addr"]),
        )

        connector.callback(_make_data(tlp="TLP:AMBER+STRICT"))

        client.get_ip.assert_not_called()
        helper.connector_logger.warning.assert_called_once_with(
            "[CONNECTOR] Entity TLP is above the connector max TLP, skipping",
            {
                "entity_id": IP_ID,
                "entity_type": "IPv4-Addr",
                "is_playbook": False,
                "tlp_levels": ["TLP:AMBER+STRICT"],
                "max_tlp": "TLP:AMBER",
            },
        )

    def test_out_of_scope_is_checked_before_tlp(self):
        helper = _make_helper()
        connector = _make_connector(helper, [DomainProcessor()])

        result = connector.callback(_make_data(entity_type="Url", tlp="TLP:RED"))

        assert result == "Entity type Url is out of scope"
        helper.connector_logger.info.assert_any_call(
            "[CONNECTOR] Entity is out of the connector scope, skipping",
            {"entity_id": IP_ID, "entity_type": "Url", "is_playbook": False},
        )


class TestCallbackErrors:
    def test_manual_error_is_logged_and_reraised_without_sending(self):
        helper = _make_helper()
        connector = _make_connector(helper, [FailingProcessor()])

        with pytest.raises(DataRetrievalError, match="source unavailable"):
            connector.callback(_make_data())

        helper.send_stix2_bundle.assert_not_called()
        helper.connector_logger.error.assert_called_once_with(
            "[CONNECTOR] Enrichment failed",
            {"entity_id": IP_ID, "is_playbook": False, "error": "source unavailable"},
        )

    def test_playbook_error_sends_the_original_bundle_then_reraises(self):
        helper = _make_helper(playbook=True)
        connector = _make_connector(helper, [FailingProcessor()])
        data = _make_data(playbook=True)
        original = [dict(obj) for obj in data["stix_objects"]]

        with pytest.raises(DataRetrievalError):
            connector.callback(data)

        helper.send_stix2_bundle.assert_called_once()
        assert _sent_objects(helper) == original

    def test_playbook_error_on_an_invalid_message_still_sends_a_bundle(self):
        helper = _make_helper(playbook=True)
        connector = _make_connector(helper, [DomainProcessor()])
        data = _make_data(playbook=True)
        del data["enrichment_entity"]

        with pytest.raises(KeyError):
            connector.callback(data)

        helper.send_stix2_bundle.assert_called_once()

    def test_playbook_error_without_stix_objects_sends_an_empty_bundle(self):
        helper = _make_helper(playbook=True)
        connector = _make_connector(helper, [DomainProcessor()])

        with pytest.raises(KeyError):
            connector.callback({"entity_id": IP_ID})

        assert _sent_objects(helper) == []

    def test_send_failure_is_logged_and_not_retried(self):
        helper = _make_helper(playbook=True)
        helper.send_stix2_bundle.side_effect = RuntimeError("queue down")
        connector = _make_connector(
            helper, [IPv4Processor(client=_ip_client({"score": 80, "asn": 13335}))]
        )

        with pytest.raises(RuntimeError, match="queue down"):
            connector.callback(_make_data(playbook=True))

        helper.send_stix2_bundle.assert_called_once()
        helper.connector_logger.error.assert_called_once_with(
            "[CONNECTOR] Failed to send the enrichment bundle",
            {"entity_id": IP_ID, "is_playbook": True, "error": "queue down"},
        )

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
        self,
    ):
        helper = _make_helper(playbook=True)
        helper.send_stix2_bundle.side_effect = ConnectionError("API down")
        connector = _make_connector(helper, [FailingProcessor()])

        with pytest.raises(DataRetrievalError, match="source unavailable"):
            connector.callback(_make_data(playbook=True))

        helper.connector_logger.error.assert_called_with(
            "[CONNECTOR] Failed to send the original bundle back",
            {"entity_id": IP_ID, "error": "API down"},
        )

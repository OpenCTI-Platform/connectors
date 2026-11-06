# pragma: no cover
# type: ignore
from typing import Any
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.internal_enrichment.base_enrichment_processor import (
    BaseEnrichmentProcessor,
)
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)


class DummyProcessor(BaseEnrichmentProcessor):
    handled_entity_types = frozenset({"IPv4-Addr", "Domain-Name"})

    def collect(self, message: EnrichmentMessage) -> Any:
        return message.stix_entity.value

    def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
        return [data] if data else []


def _make_message(
    entity_type: str = "IPv4-Addr", value: str = "v"
) -> EnrichmentMessage:
    return EnrichmentMessage.model_validate(
        {
            "enrichment_entity": {"id": "octi-id", "entity_type": entity_type},
            "stix_entity": {"type": "x", "id": "x--1", "value": value},
            "stix_objects": [],
            "from_playbook": False,
        }
    )


def _make_processor() -> DummyProcessor:
    processor = DummyProcessor()
    processor.inject_dependencies(settings=MagicMock())
    return processor


class TestBaseEnrichmentProcessor:
    def test_cannot_instantiate_abstract_class(self):
        with pytest.raises(TypeError):
            BaseEnrichmentProcessor()

    def test_inject_dependencies(self):
        settings = MagicMock()
        processor = DummyProcessor()

        processor.inject_dependencies(settings=settings)

        assert processor.settings is settings

    def test_logger_is_named_after_the_processor_module(self):
        assert DummyProcessor.logger.name == DummyProcessor.__module__

    def test_post_init_does_nothing_by_default(self):
        assert DummyProcessor().post_init() is None

    @pytest.mark.parametrize(
        "entity_type", ["IPv4-Addr", "ipv4-addr", "IPV4-ADDR", "Domain-Name"]
    )
    def test_can_process_handled_types_case_insensitively(self, entity_type):
        assert DummyProcessor().can_process(_make_message(entity_type)) is True

    def test_cannot_process_other_types(self):
        assert DummyProcessor().can_process(_make_message("Url")) is False


class TestProcess:
    def test_returns_the_transformed_data(self):
        processor = _make_processor()

        objects = processor.process(_make_message())

        assert objects == ["v"]

    def test_returns_nothing_without_data(self):
        processor = _make_processor()

        objects = processor.process(_make_message(value=""))

        assert objects == []

    def test_returns_a_list_from_any_iterable(self):
        processor = _make_processor()
        processor.transform = MagicMock(return_value=(obj for obj in ["a", "b"]))

        objects = processor.process(_make_message())

        assert objects == ["a", "b"]


class TestHandledEntityTypes:
    @pytest.mark.parametrize("handled_entity_types", [None, frozenset()])
    def test_defining_a_processor_without_handled_entity_types_raises(
        self, handled_entity_types
    ):
        namespace = {
            "collect": lambda self, message: None,
            "transform": lambda self, message, data: [],
        }
        if handled_entity_types is not None:
            namespace["handled_entity_types"] = handled_entity_types

        with pytest.raises(TypeError, match="must declare the entity types"):
            type("NoTypesProcessor", (BaseEnrichmentProcessor,), namespace)

    def test_abstract_processors_are_not_checked(self):
        class SharedProcessor(BaseEnrichmentProcessor):
            def collect(self, message: EnrichmentMessage) -> Any:
                return None

        class IPv4Processor(SharedProcessor):
            handled_entity_types = frozenset({"IPv4-Addr"})

            def transform(self, message: EnrichmentMessage, data: Any) -> list[Any]:
                return []

        assert IPv4Processor().handled_entity_types == frozenset({"IPv4-Addr"})

    def test_handled_entity_types_are_inherited(self):
        class ChildProcessor(DummyProcessor):
            pass

        assert ChildProcessor().handled_entity_types == (
            DummyProcessor.handled_entity_types
        )

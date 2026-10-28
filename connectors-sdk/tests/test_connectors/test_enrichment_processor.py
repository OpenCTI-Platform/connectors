# pragma: no cover
# type: ignore
import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.internal_enrichment.base_enrichment_processor import (
    BaseEnrichmentProcessor,
)
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from connectors_sdk.connectors.internal_enrichment.exceptions import (
    UnsupportedEntityError,
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
    processor.inject_dependencies(settings=MagicMock(), message_manager=MagicMock())
    return processor


class TestBaseEnrichmentProcessor:
    def test_cannot_instantiate_abstract_class(self):
        with pytest.raises(TypeError):
            BaseEnrichmentProcessor()

    def test_inject_dependencies(self):
        settings = MagicMock()
        message_manager = MagicMock()
        processor = DummyProcessor()

        processor.inject_dependencies(
            settings=settings, message_manager=message_manager
        )

        assert processor.settings is settings
        assert processor.message_manager is message_manager

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
    def test_sends_the_transformed_data(self):
        processor = _make_processor()

        processor.process(_make_message())

        processor.message_manager.send.assert_called_once_with(["v"])

    def test_sends_nothing_without_data(self, caplog):
        caplog.set_level(logging.INFO)
        processor = _make_processor()

        processor.process(_make_message(value=""))

        processor.message_manager.send.assert_not_called()
        assert "No enrichment data found" in [r.getMessage() for r in caplog.records]

    def test_raises_when_the_entity_cannot_be_processed(self):
        processor = _make_processor()
        processor.collect = MagicMock()

        with pytest.raises(UnsupportedEntityError, match="DummyProcessor"):
            processor.process(_make_message("Url"))

        processor.collect.assert_not_called()
        processor.message_manager.send.assert_not_called()

    def test_send_accepts_any_iterable(self):
        processor = _make_processor()

        processor.send(_make_message(), (obj for obj in ["a", "b"]))

        processor.message_manager.send.assert_called_once_with(["a", "b"])


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

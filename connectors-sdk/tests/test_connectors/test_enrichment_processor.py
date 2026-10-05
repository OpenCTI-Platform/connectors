# pragma: no cover
# type: ignore
from typing import Any
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.external_import.logger import ConnectorLogger
from connectors_sdk.connectors.internal_enrichment.base_enrichment_processor import (
    BaseEnrichmentProcessor,
)
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)


class DummyProcessor(BaseEnrichmentProcessor):
    entity_types = frozenset({"IPv4-Addr", "Domain-Name"})

    def collect(self, message: EnrichmentMessage) -> Any:
        return message.stix_entity["value"]

    def transform(self, data: Any, message: EnrichmentMessage) -> list[Any]:
        return [data]


def _make_message(entity_type: str) -> EnrichmentMessage:
    return EnrichmentMessage(
        entity_id="x--1",
        enrichment_entity={"entity_type": entity_type},
        stix_entity={"id": "x--1", "value": "v"},
        stix_objects=[],
        is_playbook=False,
    )


class TestBaseEnrichmentProcessor:
    def test_cannot_instantiate_abstract_class(self):
        with pytest.raises(TypeError):
            BaseEnrichmentProcessor()

    def test_inject_dependencies(self, mock_helper: MagicMock):
        settings = MagicMock()
        processor = DummyProcessor()

        processor.inject_dependencies(settings=settings, helper=mock_helper)

        assert processor.settings is settings
        assert isinstance(processor.logger, ConnectorLogger)

    def test_post_init_does_nothing_by_default(self):
        assert DummyProcessor().post_init() is None

    @pytest.mark.parametrize(
        "entity_type", ["IPv4-Addr", "ipv4-addr", "IPV4-ADDR", "Domain-Name"]
    )
    def test_supports_handled_types_case_insensitively(self, entity_type):
        assert DummyProcessor().supports(_make_message(entity_type)) is True

    def test_does_not_support_other_types(self):
        assert DummyProcessor().supports(_make_message("Url")) is False

import logging
from typing import Any

import pytest
from connector import AlienVaultOtxProcessor
from connectors_sdk import EnrichmentMessage

IP_ID = "ipv4-addr--0b7e1c5a-3f2d-5e6a-9b8c-1d2e3f4a5b6c"


def _make_message(entity_type: str = "IPv4-Addr") -> EnrichmentMessage:
    stix_entity = {"type": "ipv4-addr", "id": IP_ID, "value": "1.2.3.4"}
    return EnrichmentMessage.model_validate(
        {
            "enrichment_entity": {
                "id": "0b7e1c5a-3f2d-4e6a-9b8c-1d2e3f4a5b6c",
                "entity_type": entity_type,
            },
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
            "from_playbook": False,
        }
    )


def test_processor_declares_the_handled_entity_types():
    assert AlienVaultOtxProcessor.handled_entity_types == frozenset(
        {"IPv4-Addr", "Domain-Name", "Url"}
    )


@pytest.mark.parametrize(
    "entity_type, expected",
    [
        ("IPv4-Addr", True),
        ("ipv4-addr", True),
        ("Domain-Name", True),
        ("Url", True),
        ("IPv6-Addr", False),
        ("StixFile", False),
    ],
)
def test_processor_can_process_only_handled_entity_types(entity_type, expected):
    processor = AlienVaultOtxProcessor()

    assert processor.can_process(_make_message(entity_type)) is expected


def test_collect_is_a_placeholder_that_returns_nothing(
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(logging.DEBUG)
    processor = AlienVaultOtxProcessor()

    data = processor.collect(_make_message())

    assert data is None
    assert [
        (record.getMessage(), getattr(record, "attributes", None))
        for record in caplog.records
        if record.levelno == logging.DEBUG
        and record.getMessage() == "OTX lookup not implemented yet, nothing collected"
    ] == [
        (
            "OTX lookup not implemented yet, nothing collected",
            {
                "octi_id": "0b7e1c5a-3f2d-4e6a-9b8c-1d2e3f4a5b6c",
                "octi_entity_type": "IPv4-Addr",
                "from_playbook": False,
            },
        )
    ]


@pytest.mark.parametrize("data", [None, {}, {"anything": "else"}])
def test_transform_is_a_placeholder_that_returns_no_object(data: Any):
    processor = AlienVaultOtxProcessor()

    assert processor.transform(data, _make_message()) == []


def test_process_returns_no_object():
    processor = AlienVaultOtxProcessor()

    assert processor.process(_make_message()) == []

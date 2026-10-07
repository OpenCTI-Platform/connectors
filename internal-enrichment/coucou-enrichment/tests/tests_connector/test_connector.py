import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, CoucouEnrichmentConnector
from pycti import OpenCTIConnectorHelper

IPV4_ID = "ipv4-addr--5853f6a4-638f-5b4e-9b0f-ded361ae3812"
TLP_RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
OCTI_EXT = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
OCTI_SCO_EXT = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"
# Deterministic ids as computed by OpenCTI, so re-runs upsert the same objects
MALWARE_ID = "malware--40936d01-ea50-5e6d-b845-28ea0df425bb"
RELATIONSHIP_ID = "relationship--9a4950dc-4af5-5a83-b54c-779efd843b43"


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id"},
            }
        )


@pytest.fixture
def connector(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    # Only the RabbitMQ send is replaced: it records the bundles instead of publishing them
    helper.sent_bundles = []
    helper.send_stix2_bundle = lambda bundle, **_: helper.sent_bundles.append(
        json.loads(bundle)
    ) or [bundle]
    return CoucouEnrichmentConnector(config=settings, helper=helper)


def _enrichment_entity(object_marking=None) -> dict:
    """Entity as read by the helper from the OpenCTI API (`data["enrichment_entity"]`)."""
    return {
        "id": "0b3c3e5e-5c1f-4b0e-9a63-6a3c3b1c2d4e",
        "standard_id": IPV4_ID,
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
        "objectMarking": object_marking or [],
    }


def _ipv4_from_manual_trigger(labels: list[str]) -> dict:
    """IPv4 as exported by pycti `prepare_export` when the enrichment is triggered by hand."""
    return {
        "id": IPV4_ID,
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "value": "8.8.8.8",
        "x_opencti_id": "0b3c3e5e-5c1f-4b0e-9a63-6a3c3b1c2d4e",
        "x_opencti_type": "IPv4-Addr",
        "x_opencti_score": 50,
        "x_opencti_labels": labels,
    }


def _ipv4_from_playbook(labels: list[str]) -> dict:
    """IPv4 as converted to STIX by the platform (playbook bundles)."""
    return {
        "id": IPV4_ID,
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "value": "8.8.8.8",
        "object_marking_refs": [],
        "extensions": {
            OCTI_EXT: {
                "extension_type": "property-extension",
                "id": "0b3c3e5e-5c1f-4b0e-9a63-6a3c3b1c2d4e",
                "type": "IPv4-Addr",
            },
            OCTI_SCO_EXT: {
                "extension_type": "property-extension",
                "labels": labels,
                "description": "previous description",
                "score": 50,
            },
        },
    }


def _message(ipv4: dict, extra_objects=None, object_marking=None) -> dict:
    return {
        "entity_id": IPV4_ID,
        "entity_type": "IPv4-Addr",
        "event_type": "INTERNAL_ENRICHMENT",
        "enrichment_entity": _enrichment_entity(object_marking),
        "stix_entity": ipv4,
        "stix_objects": [ipv4, *(extra_objects or [])],
    }


def _sent_ipv4(connector) -> dict:
    assert len(connector.helper.sent_bundles) == 1
    return next(
        o for o in connector.helper.sent_bundles[0]["objects"] if o["id"] == IPV4_ID
    )


@pytest.mark.parametrize(
    "build_ipv4",
    [
        pytest.param(_ipv4_from_manual_trigger, id="manual_trigger"),
        pytest.param(_ipv4_from_playbook, id="playbook"),
    ],
)
def test_enrichment_sets_description_and_adds_label_keeping_existing_ones(
    connector, build_ipv4
):
    connector.process_message(_message(build_ipv4(["existing"])))

    ipv4 = _sent_ipv4(connector)
    assert ipv4["x_opencti_description"] == "coucou from enrichment"
    assert ipv4["labels"] == ["existing", "enriched"]


def test_enrichment_does_not_duplicate_label_on_rerun(connector):
    connector.process_message(_message(_ipv4_from_manual_trigger(["enriched"])))

    assert _sent_ipv4(connector)["labels"] == ["enriched"]


def test_enrichment_sends_back_all_received_objects(connector):
    marking = {
        "id": TLP_RED_ID,
        "type": "marking-definition",
        "spec_version": "2.1",
        "definition_type": "statement",
        "definition": {"statement": "keep me"},
    }

    connector.process_message(
        _message(_ipv4_from_manual_trigger([]), extra_objects=[marking])
    )

    sent_ids = [o["id"] for o in connector.helper.sent_bundles[0]["objects"]]
    assert sent_ids == [IPV4_ID, TLP_RED_ID, MALWARE_ID, RELATIONSHIP_ID]


def test_enrichment_links_ip_to_supra_coucou_malware(connector):
    connector.process_message(_message(_ipv4_from_manual_trigger([])))

    objects = {o["id"]: o for o in connector.helper.sent_bundles[0]["objects"]}
    malware = objects[MALWARE_ID]
    assert malware["type"] == "malware"
    assert malware["name"] == "supra coucou"
    assert malware["is_family"] is True
    relationship = objects[RELATIONSHIP_ID]
    assert relationship["relationship_type"] == "communicates-with"
    assert relationship["source_ref"] == MALWARE_ID
    assert relationship["target_ref"] == IPV4_ID


def test_enrichment_enriches_entity_within_max_tlp(connector):
    tlp_green = {"definition_type": "TLP", "definition": "TLP:GREEN"}

    connector.process_message(
        _message(_ipv4_from_manual_trigger([]), object_marking=[tlp_green])
    )

    assert _sent_ipv4(connector)["labels"] == ["enriched"]


def test_enrichment_skips_entity_above_max_tlp(connector):
    tlp_red = {"definition_type": "TLP", "definition": "TLP:RED"}

    connector.process_message(
        _message(_ipv4_from_manual_trigger([]), object_marking=[tlp_red])
    )

    assert connector.helper.sent_bundles == []
    # The connector logger comes from the mocked API client: the skip reason is read from its call
    _, meta = connector.helper.connector_logger.error.call_args.args
    assert "TLP of the observable is greater than MAX TLP" in meta["error_message"]

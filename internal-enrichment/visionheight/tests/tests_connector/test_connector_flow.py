from unittest.mock import MagicMock

import pytest
import stix2
from connector.connector import VisionHeightConnector
from pycti import Identity


def _make_connector(
    scope: str = "ipv4-addr,domain-name", max_tlp: str = "amber+strict"
) -> VisionHeightConnector:
    """Build a connector with all external boundaries (helper/client/converter) mocked."""
    connector = VisionHeightConnector.__new__(VisionHeightConnector)
    connector.helper = MagicMock()
    connector.helper.connect_scope = scope
    connector.client = MagicMock()
    connector.converter_to_stix = MagicMock()
    connector.config = MagicMock()
    connector.config.visionheight.max_tlp_level = max_tlp
    connector.stix_objects_list = []
    return connector


def _author() -> stix2.Identity:
    return stix2.Identity(
        id=Identity.generate_id(name="VisionHeight", identity_class="organization"),
        name="VisionHeight",
        identity_class="organization",
    )


# ---------- scope ----------


def test_entity_in_scope_true():
    connector = _make_connector()
    assert connector.entity_in_scope({"entity_id": "IPv4-Addr--abc"}) is True


def test_entity_in_scope_false():
    connector = _make_connector()
    assert connector.entity_in_scope({"entity_id": "Malware--abc"}) is False


# ---------- TLP gating ----------


def test_extract_and_check_markings_raises_when_tlp_exceeds_cap():
    connector = _make_connector(max_tlp="amber+strict")
    connector.helper.check_max_tlp.return_value = False
    # A non-TLP marking must be ignored; the TLP definition must be the one checked.
    entity = {
        "objectMarking": [
            {"definition_type": "statement", "definition": "Some statement"},
            {"definition_type": "TLP", "definition": "TLP:RED"},
        ]
    }

    with pytest.raises(ValueError):
        connector.extract_and_check_markings(entity)

    # The extracted TLP and the configured cap must be what gets checked.
    connector.helper.check_max_tlp.assert_called_once_with("TLP:RED", "amber+strict")


def test_extract_and_check_markings_passes_within_cap():
    connector = _make_connector(max_tlp="amber+strict")
    connector.helper.check_max_tlp.return_value = True
    entity = {"objectMarking": [{"definition_type": "TLP", "definition": "TLP:GREEN"}]}

    # Must not raise.
    connector.extract_and_check_markings(entity)

    connector.helper.check_max_tlp.assert_called_once_with("TLP:GREEN", "amber+strict")


def test_extract_and_check_markings_no_marking_checks_none():
    """With no markings at all, the TLP passed to the cap check must be None."""
    connector = _make_connector(max_tlp="amber+strict")
    connector.helper.check_max_tlp.return_value = True

    connector.extract_and_check_markings({"objectMarking": []})

    connector.helper.check_max_tlp.assert_called_once_with(None, "amber+strict")


# ---------- _collect_intelligence ----------


def test_collect_intelligence_ipv4_appends_author_and_new_objects():
    connector = _make_connector()
    connector.client.get_ip.return_value = {"risk": {}}
    connector.converter_to_stix.author = _author()
    new_obj = stix2.IPv4Address(value="9.9.9.9")
    connector.converter_to_stix.enrich_ip.return_value = [new_obj]

    result = connector._collect_intelligence({"type": "IPv4-Addr", "value": "1.2.3.4"})

    assert connector.converter_to_stix.author in result
    assert new_obj in result


def test_collect_intelligence_domain_appends_author_and_new_objects():
    connector = _make_connector()
    connector.client.get_domain.return_value = {"risk": {}}
    connector.converter_to_stix.author = _author()
    new_obj = stix2.DomainName(value="child.example.com")
    connector.converter_to_stix.enrich_domain.return_value = [new_obj]

    result = connector._collect_intelligence(
        {"type": "Domain-Name", "value": "example.com"}
    )

    assert connector.converter_to_stix.author in result
    assert new_obj in result


def test_collect_intelligence_unsupported_type_returns_message():
    connector = _make_connector()
    result = connector._collect_intelligence({"type": "Url", "value": "http://x"})
    assert result == "[CONNECTOR] Unsupported entity type: url"


def test_collect_intelligence_domain_api_failure_returns_input_bundle():
    connector = _make_connector()
    connector.client.get_domain.return_value = None
    connector.stix_objects_list = ["preserved"]

    result = connector._collect_intelligence(
        {"type": "Domain-Name", "value": "example.com"}
    )

    assert result == ["preserved"]


# ---------- _send_bundle ----------


def test_send_bundle_reports_count():
    connector = _make_connector()
    connector.helper.send_stix2_bundle.return_value = ["b1", "b2"]

    message = connector._send_bundle([MagicMock()])

    assert "2" in message
    connector.helper.stix2_create_bundle.assert_called_once()


# ---------- process_message ----------


def _enrichment_data(scope_id="IPv4-Addr--x", markings=None, **extra):
    data = {
        "enrichment_entity": {
            "objectMarking": markings or [],
            "entity_type": "IPv4-Addr",
        },
        "stix_objects": [],
        "stix_entity": {"id": "ipv4-addr--x", "type": "IPv4-Addr", "value": "1.2.3.4"},
        "entity_id": scope_id,
    }
    data.update(extra)
    return data


def test_process_message_in_scope_sends_bundle():
    connector = _make_connector()
    connector.helper.check_max_tlp.return_value = True
    connector.helper.send_stix2_bundle.return_value = ["b"]
    connector.converter_to_stix.author = _author()
    connector.client.get_ip.return_value = {"risk": {}}
    connector.converter_to_stix.enrich_ip.return_value = [
        stix2.IPv4Address(value="9.9.9.9")
    ]

    result = connector.process_message(_enrichment_data())

    assert "stix bundle" in result


def test_process_message_in_scope_no_information_found():
    connector = _make_connector()
    connector.helper.check_max_tlp.return_value = True
    connector.client.get_ip.return_value = None  # API failure -> empty bundle

    result = connector.process_message(_enrichment_data())

    assert result == "[CONNECTOR] No information found"


def test_process_message_tlp_exceeds_returns_error_string():
    connector = _make_connector()
    connector.helper.check_max_tlp.return_value = False
    data = _enrichment_data(
        markings=[{"definition_type": "TLP", "definition": "TLP:RED"}]
    )

    result = connector.process_message(data)

    assert result.startswith("[CONNECTOR] Error:")


def test_process_message_out_of_scope_playbook_passthrough():
    connector = _make_connector(scope="domain-name")  # IPv4 is out of scope
    connector.helper.check_max_tlp.return_value = True
    connector.helper.send_stix2_bundle.return_value = ["b"]
    data = _enrichment_data()
    data["stix_objects"] = ["passthrough"]

    result = connector.process_message(data)

    assert "stix bundle" in result


def test_process_message_out_of_scope_with_event_type_returns_error_string():
    connector = _make_connector(scope="domain-name")
    connector.helper.check_max_tlp.return_value = True
    data = _enrichment_data(event_type="create")

    result = connector.process_message(data)

    assert result.startswith("[CONNECTOR] Error:")

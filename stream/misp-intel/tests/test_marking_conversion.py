"""
Unit tests for TLP/PAP marking-definition to MISP tag conversion.

These tests do not require a real MISP instance, following the same
approach as test_misp_to_misp.py: they exercise STIXtoMISPConverter
directly against constructed STIX 2.1 bundles.
"""

from unittest.mock import MagicMock

import pytest
from misp_intel_connector.stix_to_misp_converter import STIXtoMISPConverter

TLP_RED_ID = "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1"
PAP_AMBER_ID = "marking-definition--5e5aa61b-eeb2-4a0f-8ed3-9bec293a02b1"
CUSTOM_MARKING_ID = "marking-definition--11111111-2222-3333-4444-555555555555"


def _marking_definition(marking_id, definition_type, name):
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "definition_type": definition_type,
        "name": name,
    }


def _report(object_marking_refs=None, report_types=None, object_refs=None):
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": "report--33333333-3333-3333-3333-333333333333",
        "name": "Test report",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "published": "2026-01-01T00:00:00.000Z",
        "object_marking_refs": object_marking_refs or [],
        "report_types": report_types or [],
        "object_refs": object_refs or [],
    }


def _indicator(indicator_id=None, pattern=None, object_marking_refs=None):
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id or "indicator--44444444-4444-4444-4444-444444444444",
        "name": "Malicious IP",
        "pattern": pattern or "[ipv4-addr:value = '1.2.3.4']",
        "pattern_type": "stix",
        "valid_from": "2026-01-01T00:00:00.000Z",
        "object_marking_refs": object_marking_refs or [],
    }


def _ipv4_observable(observable_id=None, value=None, object_marking_refs=None):
    return {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": observable_id or "ipv4-addr--55555555-5555-5555-5555-555555555555",
        "value": value or "5.6.7.8",
        "object_marking_refs": object_marking_refs or [],
    }


@pytest.fixture
def converter():
    helper = MagicMock()
    helper.connector_logger = MagicMock()

    config = MagicMock()
    config.misp.distribution_level = 1
    config.misp.marking_types_to_convert = "TLP,PAP"
    config.misp.get_marking_types_allowlist.return_value = {"TLP", "PAP"}

    return STIXtoMISPConverter(helper, config)


def test_tlp_marking_is_converted_to_lowercase_tlp_tag(converter):
    bundle = {
        "type": "bundle",
        "id": "bundle--66666666-6666-6666-6666-666666666666",
        "objects": [
            _marking_definition(TLP_RED_ID, "TLP", "TLP:RED"),
            _report(object_marking_refs=[TLP_RED_ID]),
        ],
    }

    misp_event = converter.convert_bundle_to_event(bundle)

    # convert_bundle_to_event() returns MISPEvent.to_dict(), which is a flat
    # dict (Tag/Attribute/Object at the top level) - there is no "Event" key
    # at this stage (that wrapper only appears in MISP server REST responses
    # and in MISPEvent.to_feed()).
    tags = [tag["name"] for tag in misp_event.get("Tag", [])]
    assert "tlp:red" in tags


def test_pap_marking_is_converted_to_pap_tag_as_is(converter):
    bundle = {
        "type": "bundle",
        "id": "bundle--77777777-7777-7777-7777-777777777777",
        "objects": [
            _marking_definition(PAP_AMBER_ID, "PAP", "PAP:AMBER"),
            _report(object_marking_refs=[PAP_AMBER_ID]),
        ],
    }

    misp_event = converter.convert_bundle_to_event(bundle)

    tags = [tag["name"] for tag in misp_event.get("Tag", [])]
    assert "PAP:AMBER" in tags


def test_report_types_are_converted_to_report_type_tags(converter):
    bundle = {
        "type": "bundle",
        "id": "bundle--88888888-8888-8888-8888-888888888888",
        "objects": [
            _report(report_types=["threat-report"]),
        ],
    }

    misp_event = converter.convert_bundle_to_event(bundle)

    tags = [tag["name"] for tag in misp_event.get("Tag", [])]
    assert "report-type:threat-report" in tags


def test_custom_marking_type_not_in_allowlist_is_skipped(converter):
    bundle = {
        "type": "bundle",
        "id": "bundle--99999999-9999-9999-9999-999999999999",
        "objects": [
            _marking_definition(CUSTOM_MARKING_ID, "internal-dist", "INTERNAL:SECRET"),
            _report(object_marking_refs=[CUSTOM_MARKING_ID]),
        ],
    }

    misp_event = converter.convert_bundle_to_event(bundle)

    tags = [tag["name"] for tag in misp_event.get("Tag", [])]
    assert "INTERNAL:SECRET" not in tags
    assert not any("internal" in tag.lower() for tag in tags)


def test_indicator_object_marking_refs_are_tagged_on_attribute(converter):
    bundle = {
        "type": "bundle",
        "id": "bundle--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "objects": [
            _marking_definition(TLP_RED_ID, "TLP", "TLP:RED"),
            _report(object_refs=["indicator--44444444-4444-4444-4444-444444444444"]),
            _indicator(object_marking_refs=[TLP_RED_ID]),
        ],
    }

    misp_event = converter.convert_bundle_to_event(bundle)

    attributes = misp_event.get("Attribute", [])
    ip_attr = next((a for a in attributes if a.get("value") == "1.2.3.4"), None)
    assert ip_attr is not None
    attr_tags = [tag["name"] for tag in ip_attr.get("Tag", [])]
    assert "tlp:red" in attr_tags


def test_observable_object_marking_refs_are_tagged_on_object_attributes(converter):
    """
    pymisp.MISPObject does not support add_tag() at the Object level
    (MISP/PyMISP#168), so marking-derived tags must be applied to each
    Attribute the Object contains, not to the Object itself.
    """
    bundle = {
        "type": "bundle",
        "id": "bundle--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "objects": [
            _marking_definition(PAP_AMBER_ID, "PAP", "PAP:AMBER"),
            _report(object_refs=["ipv4-addr--55555555-5555-5555-5555-555555555555"]),
            _ipv4_observable(object_marking_refs=[PAP_AMBER_ID]),
        ],
    }

    misp_event = converter.convert_bundle_to_event(bundle)

    misp_objects = misp_event.get("Object", [])
    ip_port_obj = next((o for o in misp_objects if o.get("name") == "ip-port"), None)
    assert ip_port_obj is not None

    object_attributes = ip_port_obj.get("Attribute", [])
    assert len(object_attributes) > 0
    for attribute in object_attributes:
        attr_tags = [tag["name"] for tag in attribute.get("Tag", [])]
        assert "PAP:AMBER" in attr_tags


def test_duplicate_indicators_with_different_markings_merge_tags(converter):
    """
    Regression test for Copilot review finding "Preserve marking tags when
    deduplicating indicators" (stix_to_misp_converter.py:652).

    Two distinct indicators that both resolve to the same MISP attribute
    (same type + value, here ip-dst / 1.2.3.4) but carry *different*
    TLP markings must both end up tagged on the single resulting attribute,
    instead of the second indicator being skipped as a "duplicate" and its
    marking silently lost.
    """
    bundle = {
        "type": "bundle",
        "id": "bundle--cccccccc-cccc-cccc-cccc-cccccccccccc",
        "objects": [
            _marking_definition(TLP_RED_ID, "TLP", "TLP:RED"),
            _marking_definition(PAP_AMBER_ID, "PAP", "PAP:AMBER"),
            _report(
                object_refs=[
                    "indicator--44444444-4444-4444-4444-444444444444",
                    "indicator--dddddddd-dddd-dddd-dddd-dddddddddddd",
                ]
            ),
            _indicator(
                indicator_id="indicator--44444444-4444-4444-4444-444444444444",
                pattern="[ipv4-addr:value = '1.2.3.4']",
                object_marking_refs=[TLP_RED_ID],
            ),
            # Same IOC value/type, but a different marking - would previously
            # be skipped entirely by _should_add_attribute(), losing PAP:AMBER.
            _indicator(
                indicator_id="indicator--dddddddd-dddd-dddd-dddd-dddddddddddd",
                pattern="[ipv4-addr:value = '1.2.3.4']",
                object_marking_refs=[PAP_AMBER_ID],
            ),
        ],
    }

    misp_event = converter.convert_bundle_to_event(bundle)

    attributes = misp_event.get("Attribute", [])
    matching = [a for a in attributes if a.get("value") == "1.2.3.4"]
    # Still deduplicated to a single MISP attribute...
    assert len(matching) == 1
    # ...but both markings must be present on it.
    attr_tags = [tag["name"] for tag in matching[0].get("Tag", [])]
    assert "tlp:red" in attr_tags
    assert "PAP:AMBER" in attr_tags


def test_duplicate_observables_with_different_markings_merge_tags(converter):
    """
    Same guarantee as test_duplicate_indicators_with_different_markings_merge_tags,
    but through the plain-observable path (_add_observable_as_attribute()),
    e.g. an observable type without a dedicated MISP object mapping.
    """
    bundle = {
        "type": "bundle",
        "id": "bundle--eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        "objects": [
            _marking_definition(TLP_RED_ID, "TLP", "TLP:RED"),
            _marking_definition(PAP_AMBER_ID, "PAP", "PAP:AMBER"),
            _report(
                object_refs=[
                    "hostname--11111111-1111-1111-1111-111111111112",
                    "hostname--22222222-2222-2222-2222-222222222223",
                ]
            ),
            {
                "type": "hostname",
                "spec_version": "2.1",
                "id": "hostname--11111111-1111-1111-1111-111111111112",
                "value": "evil.example.com",
                "object_marking_refs": [TLP_RED_ID],
            },
            {
                "type": "hostname",
                "spec_version": "2.1",
                "id": "hostname--22222222-2222-2222-2222-222222222223",
                "value": "evil.example.com",
                "object_marking_refs": [PAP_AMBER_ID],
            },
        ],
    }

    misp_event = converter.convert_bundle_to_event(bundle)

    attributes = misp_event.get("Attribute", [])
    matching = [a for a in attributes if a.get("value") == "evil.example.com"]
    assert len(matching) == 1
    attr_tags = [tag["name"] for tag in matching[0].get("Tag", [])]
    assert "tlp:red" in attr_tags
    assert "PAP:AMBER" in attr_tags

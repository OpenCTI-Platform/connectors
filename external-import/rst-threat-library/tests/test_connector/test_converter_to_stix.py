import json
from unittest.mock import MagicMock

import pytest
from connector.converter_to_stix import ConverterToStix


@pytest.fixture
def converter():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    return ConverterToStix(helper=helper)


def test_item_to_sdo_applies_configured_tlp_and_ignores_source_markings():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    converter = ConverterToStix(helper=helper, tlp_level="amber")
    item = {
        "standard_id": "intrusion-set--c8d782e1-6566-4c2b-a9f8-87a757c379a4",
        "entity_type": "Intrusion-Set",
        "name": "APT Example",
        "objectMarking": [
            {"standard_id": "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"}
        ],
    }

    sdo = converter.item_to_sdo(item, "intrusion-sets", [])

    payload = json.loads(sdo.serialize())
    assert payload["object_marking_refs"] == [converter.tlp_marking.id]
    assert converter.tlp_marking.type == "marking-definition"
    assert (
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
        not in payload["object_marking_refs"]
    )


def test_item_to_sdo_builds_intrusion_set_with_upstream_id(converter):
    item = {
        "standard_id": "intrusion-set--c8d782e1-6566-4c2b-a9f8-87a757c379a4",
        "entity_type": "Intrusion-Set",
        "name": "APT Example",
        "description": "Test intrusion set",
        "confidence": 75,
        "aliases": ["Example Group"],
        "objectLabel": ["RST Threat Library"],
    }

    sdo = converter.item_to_sdo(item, "intrusion-sets", ["RST Threat Library"])

    assert sdo is not None
    payload = json.loads(sdo.serialize())
    assert payload["id"] == item["standard_id"]
    assert payload["name"] == "APT Example"
    assert payload["aliases"] == ["Example Group"]
    assert payload["confidence"] == 75
    assert "RST Threat Library" in payload["labels"]


def test_item_to_sdo_sets_created_by_ref_when_identity_is_valid(converter):
    item = {
        "standard_id": "intrusion-set--c8d782e1-6566-4c2b-a9f8-87a757c379a4",
        "entity_type": "Intrusion-Set",
        "name": "APT Example",
        "createdBy": {
            "standard_id": "identity--a1b2c3d4-e5f6-4789-a012-3456789abcde",
            "name": "RST Cloud",
        },
    }

    sdo = converter.item_to_sdo(item, "intrusion-sets", [])

    assert sdo is not None
    payload = json.loads(sdo.serialize())
    assert payload["created_by_ref"] == (
        "identity--a1b2c3d4-e5f6-4789-a012-3456789abcde"
    )


def test_item_to_sdo_omits_created_by_ref_when_identity_is_invalid(converter):
    item = {
        "standard_id": "intrusion-set--c8d782e1-6566-4c2b-a9f8-87a757c379a4",
        "entity_type": "Intrusion-Set",
        "name": "APT Example",
        "createdBy": {
            "standard_id": "identity--not-a-uuid",
            "name": "Bad ID",
        },
    }

    sdo = converter.item_to_sdo(item, "intrusion-sets", [])

    assert sdo is not None
    payload = json.loads(sdo.serialize())
    assert "created_by_ref" not in payload


def test_item_to_sdo_returns_none_when_standard_id_missing(converter):
    item = {"entity_type": "Malware", "name": "No ID Malware"}

    assert converter.item_to_sdo(item, "malware", []) is None
    converter.helper.connector_logger.warning.assert_called()


def test_build_identity_uses_upstream_standard_id(converter):
    identity = converter.build_identity(
        {
            "standard_id": "identity--a1b2c3d4-e5f6-4789-a012-3456789abcde",
            "name": "RST Cloud",
        }
    )

    payload = json.loads(identity.serialize())
    assert payload["id"] == "identity--a1b2c3d4-e5f6-4789-a012-3456789abcde"
    assert payload["name"] == "RST Cloud"
    assert payload["identity_class"] == "organization"


def test_build_identity_honors_upstream_identity_class(converter):
    identity = converter.build_identity(
        {
            "standard_id": "identity--a1b2c3d4-e5f6-4789-a012-3456789abcde",
            "name": "Analyst",
            "identity_class": "individual",
        }
    )

    payload = json.loads(identity.serialize())
    assert payload["identity_class"] == "individual"


def test_build_identity_skips_malformed_standard_id(converter):
    identity = converter.build_identity(
        {
            "standard_id": "identity--not-a-uuid",
            "name": "Bad ID",
        }
    )

    assert identity is None
    converter.helper.connector_logger.warning.assert_called()
    args = converter.helper.connector_logger.warning.call_args.args
    assert args[0] == "Skipping invalid createdBy identity"


def test_build_identity_skips_invalid_identity_class(converter):
    identity = converter.build_identity(
        {
            "standard_id": "identity--a1b2c3d4-e5f6-4789-a012-3456789abcde",
            "name": "RST Cloud",
            "identity_class": "not-a-valid-class",
        }
    )

    assert identity is None
    converter.helper.connector_logger.warning.assert_called()


def test_build_external_references_skips_missing_source_name(converter):
    refs = converter.build_external_references(
        [
            {"url": "https://example.com/no-source"},
            {
                "source_name": "RST Cloud",
                "url": "https://example.com/ok",
                "external_id": "abc",
            },
        ]
    )

    assert len(refs) == 1
    payload = json.loads(refs[0].serialize())
    assert payload["source_name"] == "RST Cloud"
    assert payload["url"] == "https://example.com/ok"
    assert payload["external_id"] == "abc"


_UNSET_FIRST_SEEN = "1970-01-01T00:00:00.000Z"
_UNSET_LAST_SEEN = "5138-11-16T09:46:40.000Z"
_SID = "c8d782e1-6566-4c2b-a9f8-87a757c379a4"


def test_intrusion_set_omits_unset_dates_and_keeps_real_ones(converter):
    unset = converter.item_to_sdo(
        {
            "standard_id": f"intrusion-set--{_SID}",
            "entity_type": "Intrusion-Set",
            "name": "Papermill",
            "first_seen": _UNSET_FIRST_SEEN,
            "last_seen": _UNSET_LAST_SEEN,
        },
        "intrusion-sets",
        [],
    )
    unset_payload = json.loads(unset.serialize())
    assert "first_seen" not in unset_payload
    assert "last_seen" not in unset_payload

    dated = converter.item_to_sdo(
        {
            "standard_id": f"intrusion-set--{_SID}",
            "entity_type": "Intrusion-Set",
            "name": "Papermill",
            "aliases": ["Paper Mill"],
            "first_seen": "2020-03-01T00:00:00.000Z",
            "last_seen": "",
        },
        "intrusion-sets",
        [],
    )
    dated_payload = json.loads(dated.serialize())
    assert dated_payload["aliases"] == ["Paper Mill"]
    assert dated_payload["first_seen"].startswith("2020-03-01")
    assert "last_seen" not in dated_payload


def test_malware_copies_aliases_and_only_real_dates(converter):
    sdo = converter.item_to_sdo(
        {
            "standard_id": f"malware--{_SID}",
            "entity_type": "Malware",
            "name": "Example Malware",
            "is_family": True,
            "aliases": ["ex-mal"],
            "first_seen": _UNSET_FIRST_SEEN,
            "last_seen": "2022-01-15T00:00:00.000Z",
        },
        "malware",
        [],
    )
    payload = json.loads(sdo.serialize())
    assert payload["aliases"] == ["ex-mal"]
    assert "first_seen" not in payload
    assert payload["last_seen"].startswith("2022-01-15")


def test_tool_and_campaign_copy_aliases(converter):
    tool = converter.item_to_sdo(
        {
            "standard_id": f"tool--{_SID}",
            "entity_type": "Tool",
            "name": "Example Tool",
            "aliases": ["ex-tool"],
        },
        "tools",
        [],
    )
    tool_payload = json.loads(tool.serialize())
    assert tool_payload["aliases"] == ["ex-tool"]
    assert "first_seen" not in tool_payload
    assert "last_seen" not in tool_payload

    campaign = converter.item_to_sdo(
        {
            "standard_id": f"campaign--{_SID}",
            "entity_type": "Campaign",
            "name": "Pasteswitch",
            "aliases": ["Paste Switch"],
            "first_seen": _UNSET_FIRST_SEEN,
            "last_seen": _UNSET_LAST_SEEN,
            "objective": "Initial access",
        },
        "campaigns",
        [],
    )
    campaign_payload = json.loads(campaign.serialize())
    assert campaign_payload["aliases"] == ["Paste Switch"]
    assert campaign_payload["objective"] == "Initial access"
    assert "first_seen" not in campaign_payload
    assert "last_seen" not in campaign_payload

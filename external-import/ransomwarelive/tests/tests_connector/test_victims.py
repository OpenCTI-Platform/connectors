"""Unit tests for the creation of the victim Identity."""

from unittest.mock import MagicMock

import pytest
from pycti import Identity
from ransomwarelive.converter_to_stix import ConverterToStix
from ransomwarelive.ransom_conn import RansomwareAPIConnector

# ---------------------------------------------------------------------------
# ConverterToStix.process_victim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["X", "HP", "3M", "Acme Corp"])
def test_process_victim_creates_an_organization_with_the_api_name(name):
    converter = ConverterToStix("TLP:CLEAR")

    victim = converter.process_victim(victim_name=name)

    assert victim["name"] == name
    assert victim["identity_class"] == "organization"
    assert victim["id"] == Identity.generate_id(name, "organization")


# ---------------------------------------------------------------------------
# RansomwareAPIConnector.create_bundle_list
# ---------------------------------------------------------------------------


def _make_connector() -> RansomwareAPIConnector:
    """Build a connector with every optional entity disabled."""
    connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
    connector.helper = MagicMock()
    connector.config = MagicMock()
    connector.config.ransomwarelive.create_threat_actor = False
    connector.config.ransomwarelive.create_intrusion_set = False
    connector.config.ransomwarelive.create_campaign = False
    connector.config.ransomwarelive.create_report = False
    connector.config.ransomwarelive.create_leak_post_refs = False
    connector.converter_to_stix = ConverterToStix("TLP:CLEAR")
    connector.author = connector.converter_to_stix.author
    connector.processed_groups = set()
    return connector


def _item(victim) -> dict:
    return {
        "victim": victim,
        "group": "acme-ransomware",
        "country": "",
        "activity": "",
        "domain": "",
        "attackdate": "2026-10-01T00:00:00+00:00",
        "discovered": "2026-10-02T08:00:00+00:00",
    }


def test_create_bundle_list_keeps_a_two_character_victim_as_organization():
    connector = _make_connector()

    bundle_objects = connector.create_bundle_list(_item("HP"), group_data=[])

    identities = [obj for obj in bundle_objects if obj.get("type") == "identity"]
    assert [(i["name"], i["identity_class"]) for i in identities] == [
        ("HP", "organization")
    ]


@pytest.mark.parametrize("victim", [None, "", "   "])
def test_create_bundle_list_skips_a_victim_without_name(victim):
    connector = _make_connector()

    bundle_objects = connector.create_bundle_list(_item(victim), group_data=[])

    assert bundle_objects == []
    connector.helper.connector_logger.warning.assert_called_once_with(
        "Missing victim name, victim skipped",
        {"group": "acme-ransomware", "discovered": "2026-10-02T08:00:00+00:00"},
    )

"""Tests for the TLP marking the connector gives to the data it imports."""

from typing import get_args
from unittest.mock import MagicMock, patch

import pytest
import stix2
from crowdstrike_feeds_connector.connector import CrowdStrike
from crowdstrike_feeds_connector.settings import CrowdstrikeConfig
from pycti import MarkingDefinition

# The marking IDs the connector has always produced, plus TLP:CLEAR.
EXPECTED_MARKING_IDS = {
    "clear": MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
    "white": stix2.TLP_WHITE.id,
    "green": stix2.TLP_GREEN.id,
    "amber": stix2.TLP_AMBER.id,
    "amber+strict": MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
    "red": stix2.TLP_RED.id,
}

ACCEPTED_TLP_VALUES = get_args(CrowdstrikeConfig.model_fields["tlp"].annotation)


def _build_connector(tlp: str) -> MagicMock:
    """Build the connector with the given TLP, and return the actor importer mock."""
    config = MagicMock()
    config.crowdstrike = CrowdstrikeConfig(
        client_id="cid", client_secret="csecret", tlp=tlp, scopes=["actor"]
    )

    with (
        patch("crowdstrike_feeds_connector.connector.AttackTechniqueLookup"),
        patch("crowdstrike_feeds_connector.connector.BaseCrowdstrikeClient"),
        patch("crowdstrike_feeds_connector.connector.ActorImporter") as actor_importer,
    ):
        CrowdStrike(config, MagicMock())

    return actor_importer


def test_expected_marking_ids_cover_every_accepted_tlp_value():
    assert set(ACCEPTED_TLP_VALUES) == set(EXPECTED_MARKING_IDS)


@pytest.mark.parametrize("tlp", ACCEPTED_TLP_VALUES)
def test_connector_marks_data_with_the_configured_tlp(tlp):
    actor_importer = _build_connector(tlp)

    tlp_marking = actor_importer.call_args.args[4]
    assert isinstance(tlp_marking, stix2.MarkingDefinition)
    assert tlp_marking.id == EXPECTED_MARKING_IDS[tlp]


def test_connector_marks_data_with_tlp_clear_whatever_the_case():
    actor_importer = _build_connector("CLEAR")

    tlp_marking = actor_importer.call_args.args[4]
    assert tlp_marking.id == EXPECTED_MARKING_IDS["clear"]
    assert tlp_marking.x_opencti_definition == "TLP:CLEAR"

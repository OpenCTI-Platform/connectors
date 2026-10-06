from typing import get_args
from unittest.mock import MagicMock

import pytest
import stix2
from connector.connector import VisionHeightConnector
from connector.settings import TLPLevel
from connector.utils import to_canonical_tlp_marking
from pycti import Identity, OpenCTIConnectorHelper


def _make_connector(max_tlp: str = "amber+strict") -> VisionHeightConnector:
    """Build a connector wired with the *real* ``check_max_tlp``.

    The rest of the TLP gating suite mocks ``check_max_tlp``, which cannot catch a
    mismatch between the value the connector passes and what ``pycti`` accepts.
    Here the genuine implementation is used so the whole gate is exercised.
    """
    connector = VisionHeightConnector.__new__(VisionHeightConnector)
    connector.helper = MagicMock()
    connector.helper.connect_scope = "ipv4-addr,domain-name"
    connector.helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
    connector.client = MagicMock()
    connector.converter_to_stix = MagicMock()
    connector.config = MagicMock()
    connector.config.visionheight.max_tlp_level = max_tlp
    connector.stix_objects_list = []
    return connector


def _marked(tlp: str) -> dict:
    return {"objectMarking": [{"definition_type": "TLP", "definition": tlp}]}


# ---------- level -> canonical marking mapping ----------


@pytest.mark.parametrize(
    "tlp_level, expected",
    [
        pytest.param("clear", "TLP:CLEAR", id="clear"),
        pytest.param("green", "TLP:GREEN", id="green"),
        pytest.param("amber", "TLP:AMBER", id="amber"),
        pytest.param("amber+strict", "TLP:AMBER+STRICT", id="amber_strict"),
        pytest.param("red", "TLP:RED", id="red"),
    ],
)
def test_to_canonical_tlp_marking_maps_every_configurable_level(tlp_level, expected):
    """Each configurable level maps to the canonical spelling used by pycti."""
    assert to_canonical_tlp_marking(tlp_level) == expected


def test_to_canonical_tlp_marking_covers_the_whole_literal_domain():
    """Guard: adding a level to ``TLPLevel`` must not silently escape the mapping."""
    assert set(get_args(TLPLevel)) == {
        "clear",
        "green",
        "amber",
        "amber+strict",
        "red",
    }


@pytest.mark.parametrize("tlp_level", get_args(TLPLevel))
def test_canonical_marking_is_a_key_pycti_knows(tlp_level):
    """``check_max_tlp`` indexes a dict by the max TLP, so an unknown key raises.

    ``TLP:CLEAR`` is allowed under every cap, so a ``True`` result proves the
    converted cap is a valid key rather than a ``KeyError``.
    """
    max_tlp = to_canonical_tlp_marking(tlp_level)

    assert OpenCTIConnectorHelper.check_max_tlp("TLP:CLEAR", max_tlp) is True


# ---------- gating against the real check_max_tlp ----------


@pytest.mark.parametrize(
    "max_tlp, tlp",
    [
        pytest.param("amber", "TLP:RED", id="red_above_amber"),
        pytest.param("green", "TLP:AMBER", id="amber_above_green"),
        pytest.param("amber+strict", "TLP:RED", id="red_above_amber_strict"),
        pytest.param("clear", "TLP:GREEN", id="green_above_clear"),
    ],
)
def test_observable_above_cap_is_refused(max_tlp, tlp):
    """An observable marked above the configured cap must abort the enrichment."""
    connector = _make_connector(max_tlp=max_tlp)

    with pytest.raises(ValueError, match="exceeds the connector's"):
        connector.extract_and_check_markings(_marked(tlp))


@pytest.mark.parametrize(
    "max_tlp, tlp",
    [
        pytest.param("amber", "TLP:CLEAR", id="clear_under_amber"),
        pytest.param("amber", "TLP:GREEN", id="green_under_amber"),
        pytest.param("amber", "TLP:AMBER", id="amber_at_amber"),
        pytest.param("amber+strict", "TLP:AMBER+STRICT", id="strict_at_strict"),
        pytest.param("red", "TLP:RED", id="red_at_red"),
    ],
)
def test_observable_at_or_below_cap_is_allowed(max_tlp, tlp):
    """An observable marked at or below the cap must pass the gate silently."""
    connector = _make_connector(max_tlp=max_tlp)

    connector.extract_and_check_markings(_marked(tlp))


@pytest.mark.parametrize(
    "opencti_entity",
    [
        pytest.param({}, id="no_object_marking_key"),
        pytest.param({"objectMarking": []}, id="empty_object_marking"),
        pytest.param(
            {"objectMarking": [{"definition_type": "statement", "definition": "x"}]},
            id="non_tlp_marking_only",
        ),
    ],
)
def test_unmarked_observable_is_allowed(opencti_entity):
    """No TLP marking means no cap to enforce: ``check_max_tlp`` returns early."""
    connector = _make_connector(max_tlp="amber+strict")

    connector.extract_and_check_markings(opencti_entity)


# ---------- regression ----------


def test_marked_observable_does_not_raise_key_error():
    """Regression: the lowercase cap used to blow up inside ``check_max_tlp``.

    ``pycti`` ends on ``allowed_tlps[max_tlp.upper()]`` and that table is keyed by
    ``TLP:CLEAR``/``TLP:GREEN``/``TLP:AMBER``/``TLP:AMBER+STRICT``/``TLP:RED``, so
    passing the settings value as-is looked up the missing key ``AMBER+STRICT``
    and raised ``KeyError``. It only surfaced on observables actually carrying a
    TLP marking, since ``check_max_tlp`` returns early when ``tlp is None``.
    """
    # The old, buggy call: the lowercase settings value straight from the config.
    with pytest.raises(KeyError):
        OpenCTIConnectorHelper.check_max_tlp("TLP:GREEN", "amber+strict")

    # The fixed path converts the cap first, so the gate simply passes.
    connector = _make_connector(max_tlp="amber+strict")
    connector.extract_and_check_markings(_marked("TLP:GREEN"))


def test_process_message_enriches_marked_observable_within_cap():
    """End to end: a marked observable within the cap must reach enrichment.

    Before the fix, ``process_message`` caught the ``KeyError`` from the TLP gate
    and returned an error string, so *every* marked observable was silently left
    unenriched.
    """
    connector = _make_connector(max_tlp="amber+strict")
    connector.helper.send_stix2_bundle.return_value = ["bundle"]
    connector.converter_to_stix.author = stix2.Identity(
        id=Identity.generate_id(name="VisionHeight", identity_class="organization"),
        name="VisionHeight",
        identity_class="organization",
    )
    connector.client.get_ip.return_value = {"risk": {}}
    connector.converter_to_stix.enrich_ip.return_value = [
        stix2.IPv4Address(value="9.9.9.9")
    ]

    result = connector.process_message(
        {
            "enrichment_entity": {
                "objectMarking": [
                    {"definition_type": "TLP", "definition": "TLP:AMBER"}
                ],
                "entity_type": "IPv4-Addr",
            },
            "stix_objects": [],
            "stix_entity": {
                "id": "ipv4-addr--x",
                "type": "IPv4-Addr",
                "value": "1.2.3.4",
            },
            "entity_id": "IPv4-Addr--x",
        }
    )

    assert "stix bundle" in result
    connector.client.get_ip.assert_called_once_with("1.2.3.4")

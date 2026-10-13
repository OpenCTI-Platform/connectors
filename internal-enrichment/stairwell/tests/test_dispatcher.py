from unittest.mock import MagicMock

import pytest
from connector.enricher import Dispatcher
from connector.stairwell import StairwellClient


def _dispatcher(max_tlp="TLP:AMBER"):
    client = StairwellClient.__new__(StairwellClient)
    client._base_url = "https://app.stairwell.com"
    client._timeout = 30
    client._session = MagicMock()
    d = Dispatcher(MagicMock(), client, "amber", max_tlp=max_tlp)
    d.file = MagicMock()
    d.file.enrich = MagicMock(return_value="enriched")
    return d, client


def _file_observable(*tlps):
    return {
        "entity_type": "StixFile",
        "hashes": [{"algorithm": "SHA-256", "hash": "a" * 64}],
        "objectMarking": [
            {"definition_type": "TLP", "definition": tlp} for tlp in tlps
        ],
    }


@pytest.mark.parametrize(
    "markings, max_tlp, allowed",
    [
        ((), "TLP:AMBER", True),
        (("TLP:CLEAR",), "TLP:AMBER", True),
        (("TLP:GREEN",), "TLP:AMBER", True),
        (("TLP:AMBER",), "TLP:AMBER", True),
        (("TLP:AMBER+STRICT",), "TLP:AMBER", False),
        (("TLP:RED",), "TLP:AMBER", False),
        (("TLP:GREEN", "TLP:RED"), "TLP:AMBER", False),
        (("TLP:RED",), "TLP:RED", True),
        (("TLP:AMBER",), "TLP:GREEN", False),
    ],
)
def test_max_tlp_gates_enrichment(markings, max_tlp, allowed):
    d, client = _dispatcher(max_tlp=max_tlp)
    observable = _file_observable(*markings)
    if allowed:
        assert d.dispatch(observable) == "enriched"
        d.file.enrich.assert_called_once_with(observable)
    else:
        with pytest.raises(ValueError, match="max TLP"):
            d.dispatch(observable)
        d.file.enrich.assert_not_called()
        client._session.get.assert_not_called()


def test_non_tlp_markings_are_ignored():
    d, _ = _dispatcher(max_tlp="TLP:GREEN")
    observable = _file_observable("TLP:GREEN")
    observable["objectMarking"].append(
        {"definition_type": "PAP", "definition": "PAP:RED"}
    )
    assert d.dispatch(observable) == "enriched"


def test_unknown_tlp_on_observable_is_refused():
    d, _ = _dispatcher(max_tlp="TLP:RED")
    with pytest.raises(ValueError, match="max TLP"):
        d.dispatch(_file_observable("TLP:SOMETHING-CUSTOM"))


@pytest.mark.parametrize("value", ["amber", "TLP:amber", "tlp:AMBER"])
def test_max_tlp_accepts_short_and_mixed_case_forms(value):
    d, _ = _dispatcher(max_tlp=value)
    assert d.dispatch(_file_observable("TLP:AMBER")) == "enriched"
    with pytest.raises(ValueError):
        d.dispatch(_file_observable("TLP:RED"))


def test_invalid_max_tlp_fails_at_construction():
    with pytest.raises(ValueError, match="STAIRWELL_MAX_TLP_LEVEL"):
        _dispatcher(max_tlp="TLP:PURPLE")


@pytest.mark.parametrize(
    "entity_type, supported",
    [
        ("StixFile", True),
        ("Domain-Name", True),
        ("IPv4-Addr", True),
        ("IPv6-Addr", True),
        ("Autonomous-System", True),
        # Not in CONNECTOR_SCOPE; enriching it would emit a `file` SCO under an
        # `artifact--` id.
        ("Artifact", False),
        ("Url", False),
    ],
)
def test_supported_entity_types_match_the_connector_scope(entity_type, supported):
    d, _ = _dispatcher()
    assert d.supports({"entity_type": entity_type}) is supported

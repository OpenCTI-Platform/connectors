"""Regression tests for TIDE HOST records without a `domain` field (#7400)."""

from unittest.mock import MagicMock

import pytest
from connector import Infoblox
from pycti import Indicator


@pytest.fixture
def connector() -> Infoblox:
    """Infoblox connector built with a mocked config and a mocked helper."""
    config = MagicMock()
    config.infoblox.marking_definition = "TLP:AMBER+STRICT"
    helper = MagicMock()
    return Infoblox(config=config, helper=helper)


def make_host_threat(**fields) -> dict:
    """Build a TIDE HOST threat record; `fields` overrides or adds keys."""
    threat = {
        "id": "id-host",
        "type": "HOST",
        "threat_level": 80,
        "confidence": 90,
        "class": "Malware",
        "property": "MalwareC2",
        "extended": {"notes": "some notes"},
        "detected": "2024-05-01T10:20:21.392Z",
        "imported": "2024-05-02T11:21:22.123Z",
    }
    threat.update(fields)
    return threat


def objects_of_type(bundle, stix_type) -> list:
    """Return the objects of one STIX type in a bundle."""
    return [obj for obj in bundle.objects if obj["type"] == stix_type]


def test_host_threat_with_domain_keeps_the_domain(connector):
    """A HOST record with `domain` is converted as before."""
    threat = make_host_threat(domain="bad.example.com", host="www.bad.example.com")

    bundle, _ = connector.create_stix_bundle("", "", {"threat": [threat]})

    (indicator,) = objects_of_type(bundle, "indicator")
    (domain,) = objects_of_type(bundle, "domain-name")
    assert indicator.pattern == "[domain-name:value = 'bad.example.com']"
    assert indicator.id == Indicator.generate_id(
        "[domain-name:value = 'bad.example.com']"
    )
    assert domain.value == "bad.example.com"


def test_host_threat_without_domain_uses_host(connector):
    """#7400: a HOST record without `domain` no longer raises KeyError: 'domain'."""
    threat = make_host_threat(host="c2.bad.example.org")

    bundle, _ = connector.create_stix_bundle("", "", {"threat": [threat]})

    (indicator,) = objects_of_type(bundle, "indicator")
    (domain,) = objects_of_type(bundle, "domain-name")
    assert indicator.name == "c2.bad.example.org"
    assert indicator.pattern == "[domain-name:value = 'c2.bad.example.org']"
    assert domain.value == "c2.bad.example.org"
    assert len(objects_of_type(bundle, "relationship")) == 1


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({}, id="no-domain-no-host"),
        pytest.param({"domain": "", "host": None}, id="empty-values"),
    ],
)
def test_host_threat_without_any_name_is_skipped_and_others_are_kept(connector, fields):
    """#7400: a HOST record with no usable name is skipped with one warning, the rest is sent."""
    bad = make_host_threat(**fields)
    good = make_host_threat(id="id-good", domain="ok.example.net")

    bundle, all_threats = connector.create_stix_bundle("", "", {"threat": [bad, good]})

    assert len(all_threats) == 2
    assert [i.name for i in objects_of_type(bundle, "indicator")] == ["ok.example.net"]
    warning = connector.helper.connector_logger.warning
    assert warning.call_count == 1
    message, context = warning.call_args.args
    assert message == "Skipping Infoblox HOST threat without a domain or host value"
    assert context == {"threat_id": "id-host"}

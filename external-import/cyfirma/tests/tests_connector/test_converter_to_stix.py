from unittest.mock import MagicMock

import pytest
import stix2
from connector.converter_to_stix import ConverterToStix
from pycti import Identity, MarkingDefinition, StixCoreRelationship

SOURCE_ID = "indicator--7e1f3a0c-5b0e-4a53-9d37-0c6f4f3f6a11"
TARGET_ID = "vulnerability--2b9c7d44-1f0a-4f4e-8a55-3e6b8d1c9a22"


@pytest.fixture
def helper():
    return MagicMock()


@pytest.fixture
def converter(helper):
    return ConverterToStix(helper, tlp_level="clear")


def test_init_creates_author_and_marking(helper):
    conv = ConverterToStix(helper, tlp_level="green")

    assert conv.helper is helper
    assert conv.author.name == "CYFIRMA"
    assert conv.tlp_marking.id == stix2.TLP_GREEN.id


def test_create_author():
    author = ConverterToStix.create_author()

    assert author.name == "CYFIRMA"
    assert author.identity_class == "organization"
    assert author.id == Identity.generate_id(
        name="CYFIRMA", identity_class="organization"
    )
    assert author.x_opencti_aliases == ["cyfirma"]
    assert author.contact_information == "https://www.cyfirma.com/contact-us"


@pytest.mark.parametrize(
    "level, expected",
    [
        ("white", stix2.TLP_WHITE),
        ("green", stix2.TLP_GREEN),
        ("amber", stix2.TLP_AMBER),
        ("red", stix2.TLP_RED),
    ],
)
def test_standard_tlp_levels(helper, level, expected):
    assert ConverterToStix(helper, tlp_level=level).tlp_marking.id == expected.id


@pytest.mark.parametrize(
    "level, definition",
    [("clear", "TLP:CLEAR"), ("amber+strict", "TLP:AMBER+STRICT")],
)
def test_custom_tlp_levels(helper, level, definition):
    marking = ConverterToStix(helper, tlp_level=level).tlp_marking

    assert marking.id == MarkingDefinition.generate_id("TLP", definition)
    assert marking.x_opencti_definition_type == "TLP"
    assert marking.x_opencti_definition == definition


def test_tlp_level_is_case_insensitive(helper):
    conv = ConverterToStix(helper, tlp_level="AMBER")

    assert conv.tlp_marking.id == stix2.TLP_AMBER.id


def test_unknown_tlp_level_raises(helper):
    with pytest.raises(KeyError):
        ConverterToStix(helper, tlp_level="purple")


# --------------------------------------------------------------------------- #
# create_relationship
# --------------------------------------------------------------------------- #


def test_create_relationship(converter):
    rel = converter.create_relationship(SOURCE_ID, "related-to", TARGET_ID)

    assert rel.relationship_type == "related-to"
    assert rel.source_ref == SOURCE_ID
    assert rel.target_ref == TARGET_ID
    assert rel.created_by_ref == converter.author.id
    assert rel.id == StixCoreRelationship.generate_id(
        "related-to", SOURCE_ID, TARGET_ID
    )


# --------------------------------------------------------------------------- #
# IP / domain helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2001:db8::1", True),
        ("::1", True),
        ("192.168.0.1", False),
        ("example.com", False),
        ("", False),
    ],
)
def test_is_ipv6(value, expected):
    assert ConverterToStix._is_ipv6(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("192.168.0.1", True),
        ("8.8.8.8", True),
        ("256.1.1.1", False),
        ("2001:db8::1", False),
        ("example.com", False),
    ],
)
def test_is_ipv4(value, expected):
    assert ConverterToStix._is_ipv4(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("not a domain", False),
        ("192.168.0.1", False),
        ("", False),
    ],
)
def test_is_domain(value, expected):
    assert ConverterToStix._is_domain(value) is expected


# --------------------------------------------------------------------------- #
# create_obs
# --------------------------------------------------------------------------- #


def test_create_obs_ipv6(converter):
    obs = converter.create_obs("2001:db8::1")

    assert isinstance(obs, stix2.IPv6Address)
    assert obs.value == "2001:db8::1"
    assert obs.x_opencti_created_by_ref == converter.author["id"]


def test_create_obs_ipv4(converter):
    obs = converter.create_obs("8.8.8.8")

    assert isinstance(obs, stix2.IPv4Address)
    assert obs.value == "8.8.8.8"
    assert obs.x_opencti_created_by_ref == converter.author["id"]


def test_create_obs_domain(converter):
    obs = converter.create_obs("example.com")

    assert isinstance(obs, stix2.DomainName)
    assert obs.value == "example.com"
    assert obs.x_opencti_created_by_ref == converter.author["id"]


@pytest.mark.parametrize("value", ["not a valid value!!", "", "999.999.999.999"])
def test_create_obs_invalid_value_logs_error(converter, helper, value):
    assert converter.create_obs(value) is None

    helper.connector_logger.error.assert_called_once()
    assert helper.connector_logger.error.call_args.args[1] == {"value": value}

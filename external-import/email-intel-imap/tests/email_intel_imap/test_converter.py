from unittest.mock import Mock

import pytest
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.converter import ConnectorConverter
from stix2 import TLPMarking


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter(mocked_helper: Mock):
    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)

    assert converter.author_name
    assert converter.author_description


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_author(mocked_helper: Mock):
    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)

    assert converter.author.name == converter.author_name
    assert converter.author.description == converter.author_description
    assert converter.author.identity_class == "organization"
    assert converter.author.type == "identity"


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_tlp_marking(mocked_helper: Mock):
    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)

    assert converter.tlp_marking.definition == TLPMarking(tlp="white")
    assert converter.tlp_marking.definition_type == "tlp"
    assert converter.tlp_marking.name == "TLP:WHITE"
    assert converter.tlp_marking.type == "marking-definition"


import json
import sys
from pathlib import Path

import pytest

sys.path.append(str((Path(__file__).resolve().parent.parent / "src")))

from tenable_vuln_management.converter_to_stix import ConverterToStix, tlp_marking_definition_handler

from tenable_vuln_management.models.tenable import Asset

from unittest.mock import MagicMock

BASE_DIR = Path(__file__).parent
RESPONSE_FILE = BASE_DIR / "resources" / "tenable_api_response.json"


def load_responses():
    # Load the JSON file
    with open(RESPONSE_FILE, "r") as file:
        responses = json.load(file)
    return responses

@pytest.fixture
def mock_helper():
    return MagicMock()

@pytest.fixture
def fake_asset():
    return Asset.model_validate_json(
        '''
        {
        "device_type": "general-purpose",
        "fqdn": "sharepoint2016.target.example.com",
        "hostname": "sharepoint2016",
        "uuid": "53ed0fa2-ccd5-4d2e-92ee-c072635889e3",
        "ipv4": "203.0.113.71",
        "ipv6": "2001:db8:199e:6fb9:2edd:67f0:3f30:c7",
        "mac_address": "00:50:56:a6:22:93",
        "operating_system": [
            "Microsoft Windows Server 2016 Standard"
        ],
        "network_id": "00000000-0000-0000-0000-000000000000",
        "tracked": true
        }
        '''
    )


def test_tlp_marking_definition_handler_should_fails_with_unsupported_TLP():
    # GIVEN: An invalid TLP marking definition
    invalid_marking = "TLP:BLUE"

    # WHEN/THEN: We expect a ValueError when calling the function
    with pytest.raises(ValueError) as exc_info:
        tlp_marking_definition_handler(invalid_marking)

    # Assert that the exception message is as expected
    assert str(exc_info.value) == "Unsupported TLP marking: TLP:BLUE"

def test_converter_to_stix_make_author(mock_helper):
    # Given a converter to stix instance
    converter_to_stix=ConverterToStix(helper=mock_helper)
    # When calling make_author
    author=converter_to_stix.make_author()
    # Then a valid Author should be returned
    assert converter_to_stix.author == author


def test_converter_to_stix_make_system_from_asset(mock_helper, fake_asset):
    # Given a converter to stix instance
    # and a valid asset instance
    converter_to_stix=ConverterToStix(helper=mock_helper)
    asset=fake_asset
    # When calling make_author
    system=converter_to_stix.make_system(asset=asset)
    # Then a valid System should be returned
    assert system.author == converter_to_stix.author



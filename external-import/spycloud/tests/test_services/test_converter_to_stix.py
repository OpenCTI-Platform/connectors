import sys
from datetime import datetime
from pathlib import Path

sys.path.append(str((Path(__file__).resolve().parent.parent.parent / "src")))

from unittest.mock import Mock

import pytest
from connector.models.spycloud import BreachCatalog, BreachRecord
from connector.services.converter_to_stix import ConverterToStix


@pytest.fixture
def mock_converter_to_stix():
    helper = Mock()
    config = Mock()

    helper.connect_name = "Spycloud Test"
    return ConverterToStix(helper=helper, config=config)


def test_converter_to_stix_author(mock_converter_to_stix):
    # Given a ConverterToStix instance
    # When accessing author attribute
    # Then a valid Author should be returned
    assert mock_converter_to_stix.author.name == "Spycloud Test"
    assert (
        mock_converter_to_stix.author.description
        == "SpyCloud external import connector"
    )
    assert mock_converter_to_stix.author.identity_class == "organization"


def test_converter_to_stix_create_author(mock_converter_to_stix):
    # Given a ConverterToStix instance
    # When calling _create_author
    author = mock_converter_to_stix._create_author(
        name="Test Author",
        description="Test description",
        identity_class="organization",
    )
    # Then a valid Author should be returned
    assert author.name == "Test Author"
    assert author.description == "Test description"
    assert author.identity_class == "organization"


def test_converter_to_stix_create_incident(mock_converter_to_stix):
    # Given a ConverterToStix instance and Spycloud breach catalog + breach record
    breach_catalog = BreachCatalog(
        **{
            # Required fields
            "id": 67701,
            "uuid": "8d0edaea-56e4-4731-9ceb-a8f00d23b788",
            "title": "Telegram Combo Cloudxurl",
            "description": "On an unknown date, personally identifiable information (PII) data allegedly belonging to individuals/consumers based in an unknown country was leaked online. The data contains salts, passwords, email addresses, usernames, and additional personal information. This breach is being publicly shared on the Internet.",
            "type": "PUBLIC",
            "num_records": 234444786,
            "spycloud_publish_date": "2024-12-04T00:00:00Z",
            "acquisition_date": "2024-11-22T00:00:00Z",
            "assets": {
                "target_url": 223282538,
                "salt": 90,
                "username": 135505898,
                "password": 231369461,
                "email": 98941453,
            },
            "confidence": 3,
            "breach_main_category": "breach",
            "breach_category": "exfiltrated",
            "sensitive_source": False,
            "consumer_category": "publicexposure",
            "tlp": "amber",
            "short_title": "Telegram Combo Cloudxurl",
            # Optional fields
            "combo_list_flag": "YES",
            "site_description": "This PII data allegedly belongs to individuals/consumers based in an unknown country.",
            "site": "n/a",
        }
    )
    breach_record = BreachRecord(
        **{
            # Required fields
            "document_id": "0812cbe0-62d6-47b3-af9f-d5ed0aae6e3f",
            "source_id": 67701,
            "spycloud_publish_date": "2024-12-04T00:00:00Z",
            "severity": 20,
            # Optional fields
            "email": "grolfson@example.org",
            "password": "jaXwWsR:v6Tup7.",
            "target_url": "http://demo.inertiajs.com/users/3/edit",
            "email_domain": "example.org",
            "email_username": "grolfson",
            "domain": "example.org",
            "target_domain": "inertiajs.com",
            "target_subdomain": "demo.inertiajs.com",
            "password_type": "plaintext",
            "password_plaintext": "jaXwWsR:v6Tup7.",
            "sighting": 4,
        }
    )
    # When calling create_incident
    incident = mock_converter_to_stix.create_incident(
        breach_catalog=breach_catalog,
        breach_record=breach_record,
    )
    # Then a valid Incident should be returned
    assert incident.name is not None
    assert incident.description is not None
    assert incident.source == "Telegram Combo Cloudxurl"
    assert incident.severity == "high"
    assert incident.incident_type == "data-breach"
    assert incident.author == mock_converter_to_stix.author
    assert incident.created_at == datetime.fromisoformat("2024-12-04T00:00:00Z")
    assert incident.updated_at == datetime.fromisoformat("2024-12-04T00:00:00Z")

import datetime
from unittest.mock import Mock

import pycti
import pytest
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.converter import ConnectorConverter
from stix2 import TLPMarking
from stix2.utils import STIXdatetime


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter(mocked_helper: Mock) -> None:
    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)

    assert converter.author_name
    assert converter.author_description


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_author(mocked_helper: Mock) -> None:
    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)

    assert converter.author.name == converter.author_name
    assert converter.author.description == converter.author_description
    assert converter.author.identity_class == "organization"
    assert converter.author.type == "identity"


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_tlp_marking(mocked_helper: Mock) -> None:
    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)

    assert converter.tlp_marking.definition == TLPMarking(tlp="white")
    assert converter.tlp_marking.definition_type == "tlp"
    assert converter.tlp_marking.name == "TLP:WHITE"
    assert converter.tlp_marking.type == "marking-definition"


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_to_stix(mocked_helper: Mock) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    mocked_email = Mock(subject="Test Report", date=published, text="Test Content")

    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)

    report = list(converter.to_stix(entity=mocked_email))
    assert len(report) == 1

    assert report[0].id == pycti.Report.generate_id(
        name="Test Report", published=published
    )
    assert report[0].name == "Test Report"
    assert report[0].report_types == ["threat-report"]
    assert report[0].published == STIXdatetime(2025, 4, 16, 10, 10, 10)
    assert report[0].created_by_ref == converter.author.id
    assert report[0].object_refs == [converter.author.id]
    assert report[0].object_marking_refs == [converter.tlp_marking.id]
    assert report[0].x_opencti_content == "Test Content"


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_to_stix_no_subject(mocked_helper: Mock) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    mocked_email = Mock(
        subject="", date=published, text="Test Content", from_="from_@email.com"
    )

    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)

    report = list(converter.to_stix(entity=mocked_email))
    assert len(report) == 1

    assert report[0].id == pycti.Report.generate_id(
        name="<no subject> from from_@email.com", published=published
    )
    assert report[0].name == "<no subject> from from_@email.com"
    assert report[0].report_types == ["threat-report"]
    assert report[0].published == STIXdatetime(2025, 4, 16, 10, 10, 10)
    assert report[0].created_by_ref == converter.author.id
    assert report[0].object_refs == [converter.author.id]
    assert report[0].object_marking_refs == [converter.tlp_marking.id]
    assert report[0].x_opencti_content == "Test Content"


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_to_stix_with_error(mocked_helper: Mock) -> None:
    converter = ConnectorConverter(config=ConnectorConfig(), helper=mocked_helper)
    report = list(converter.to_stix(entity=Mock()))
    assert len(report) == 0
    mocked_helper.connector_logger.warning.assert_called_with(
        "An error occurred while creating the Report, skipping...",
        {
            "error": "Object of type 'Mock' is not JSON serializable",
        },
    )

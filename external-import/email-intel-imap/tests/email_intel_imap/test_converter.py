import base64
import datetime
from unittest.mock import Mock

import pycti
import pytest

from email_intel_imap.converter import ConnectorConverter
from stix2 import TLPMarking
from stix2.utils import STIXdatetime


@pytest.fixture(name="converter")
def fixture_converter(mocked_helper: Mock) -> ConnectorConverter:
    return ConnectorConverter(
        helper=mocked_helper,
        author_name="Email Intel IMAP",
        author_description="Email Intel IMAP Connector",
        tlp_level="white",
    )


def test_converter_author(converter: ConnectorConverter) -> None:
    assert converter.author.name == "Email Intel IMAP"
    assert converter.author.description == "Email Intel IMAP Connector"
    assert converter.author.identity_class == "organization"
    assert converter.author.type == "identity"


def test_converter_tlp_marking(converter: ConnectorConverter) -> None:
    assert converter.tlp_marking.definition == TLPMarking(tlp="white")
    assert converter.tlp_marking.definition_type == "tlp"
    assert converter.tlp_marking.name == "TLP:WHITE"
    assert converter.tlp_marking.type == "marking-definition"


def test_converter_to_stix(converter: ConnectorConverter) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    mocked_email = Mock(
        subject="Test Report", date=published, text="Test Content", attachments=[]
    )

    report = list(converter.to_stix_objects(entity=mocked_email))
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


def test_converter_to_stix_no_subject(converter: ConnectorConverter) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    mocked_email = Mock(
        subject="",
        date=published,
        text="Test Content",
        from_="from_@email.com",
        attachments=[],
    )

    report = list(converter.to_stix_objects(entity=mocked_email))
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


def test_converter_to_stix_with_error(converter: ConnectorConverter) -> None:
    report = list(converter.to_stix_objects(entity=Mock()))
    assert len(report) == 0
    converter.helper.connector_logger.warning.assert_called_with(
        "An error occurred while creating the Report, skipping...",
        {
            "error": "'Mock' object is not iterable",
        },
    )


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_to_stix_with_attachment(converter: ConnectorConverter) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    pdf_file = Mock(
        filename="test.pdf",
        content_type="application/pdf",
        content_disposition="attachment",
        payload=b"%PDF-1.4\nTest PDF Content",
    )
    csv_file = Mock(
        filename="test.csv",
        content_type="text/csv",
        content_disposition="attachment",
        payload=b"Test CSV Content",
    )
    mocked_email = Mock(
        subject="",
        date=published,
        text="Test Content",
        from_="from_@email.com",
        attachments=[],
    )

    # No file
    report = list(converter.to_stix_objects(entity=mocked_email))[0]
    assert "x_opencti_files" not in report

    # 1 file
    mocked_email.attachments = [pdf_file]
    report = list(converter.to_stix_objects(entity=mocked_email))[0]
    assert report.x_opencti_files == [
        {
            "name": "test.pdf",
            "mime_type": "application/pdf",
            "data": base64.b64encode(b"%PDF-1.4\nTest PDF Content"),
        }
    ]

    # 2 files
    mocked_email.attachments = [pdf_file, csv_file]
    report = list(converter.to_stix_objects(entity=mocked_email))[0]
    assert report.x_opencti_files == [
        {
            "name": "test.pdf",
            "mime_type": "application/pdf",
            "data": base64.b64encode(b"%PDF-1.4\nTest PDF Content"),
        },
        {
            "name": "test.csv",
            "mime_type": "text/csv",
            "data": base64.b64encode(b"Test CSV Content"),
        },
    ]


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_converter_to_stix_with_attachment__mime_type_not_in_config(
    converter: ConnectorConverter,
) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    mocked_email = Mock(
        subject="",
        date=published,
        text="Test Content",
        from_="from_@email.com",
        attachments=[
            Mock(
                filename="test.jpeg",
                content_type="image/jpeg",  # Not in attachments_mime_types
                content_disposition="attachment",
                payload=b"\xff\xd8\xff\x00",
            )
        ],
    )

    assert (
        "x_opencti_files" not in list(converter.to_stix_objects(entity=mocked_email))[0]
    )

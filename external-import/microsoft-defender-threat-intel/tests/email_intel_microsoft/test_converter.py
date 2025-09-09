import base64
import datetime
from unittest.mock import Mock

import pycti
import pytest
from base_connector import ConnectorWarning
from email_intel_microsoft.converter import ConnectorConverter
from stix2 import TLPMarking
from stix2.utils import STIXdatetime


@pytest.fixture(name="converter")
def fixture_converter(mocked_helper: Mock) -> ConnectorConverter:
    return ConnectorConverter(
        helper=mocked_helper,
        author_name="Email Intel Microsoft",
        author_description="Email Intel Microsoft Connector",
        tlp_level="white",
    )


def test_converter_author(converter: ConnectorConverter) -> None:
    assert converter.author.name == "Email Intel Microsoft"
    assert converter.author.description == "Email Intel Microsoft Connector"
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
        subject="Test Report",
        received_date_time=published,
        body=Mock(content="Test Content"),
        attachments=[],
        from_=Mock(email_address=Mock(address="email@test.com")),
    )

    report = list(converter.to_stix_objects(entity=mocked_email))
    assert len(report) == 1

    assert report[0].id == pycti.Report.generate_id(
        name="Test Report", published=published
    )
    assert report[0].name == "Test Report"
    assert report[0].report_types == ["threat-report"]
    assert report[0].published == STIXdatetime(2025, 4, 16, 10, 10, 10)
    assert report[0].object_marking_refs == [converter.tlp_marking.id]
    assert report[0].x_opencti_content == "Test Content"
    assert report[0].description == (
        "**Email Received From**: email@test.com  \n"
        "**Email Received At**: 2025-04-16 10:10:10  \n"
        "**Email Subject**: Test Report  \n"
        "**Email Attachment Count**: 0  \n"
        "  \n"
        "Please consult the content section to view the email content."
    )


def test_converter_to_stix_no_subject(converter: ConnectorConverter) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    mocked_email = Mock(
        subject="",
        received_date_time=published,
        body=Mock(content="Test Content"),
        from_=Mock(email_address=Mock(address="from_@email.com")),
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
    assert report[0].object_marking_refs == [converter.tlp_marking.id]
    assert report[0].x_opencti_content == "Test Content"
    assert report[0].description == (
        "**Email Received From**: from_@email.com  \n"
        "**Email Received At**: 2025-04-16 10:10:10  \n"
        "**Email Subject**: <no subject> from from_@email.com  \n"
        "**Email Attachment Count**: 0  \n"
        "  \n"
        "Please consult the content section to view the email content."
    )


def test_converter_to_stix_with_error(converter: ConnectorConverter) -> None:
    with pytest.raises(ConnectorWarning) as exc_info:
        report = list(converter.to_stix_objects(entity=Mock(attachments=None)))
        assert len(report) == 0
    assert exc_info.value.args == (
        "An error occurred while creating the Report, skipping...",
    )


@pytest.mark.usefixtures("mock_email_intel_microsoft_config")
def test_converter_to_stix_with_attachment(converter: ConnectorConverter) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    pdf_file = Mock()
    pdf_file.name = "test.pdf"
    pdf_file.content_type = "application/pdf"
    pdf_file.content_bytes = base64.b64encode(b"%PDF-1.4\nTest PDF Content")

    csv_file = Mock()
    csv_file.name = "test.csv"
    csv_file.content_type = "text/csv"
    csv_file.content_bytes = base64.b64encode(b"Test CSV Content")

    mocked_email = Mock(
        subject="",
        received_date_time=published,
        body=Mock(content="Test Content"),
        from_=Mock(email_address=Mock(address="from_@email.com")),
        attachments=[],
    )

    # No file
    report = list(converter.to_stix_objects(entity=mocked_email))[0]
    assert "x_opencti_files" not in report
    assert report.description == (
        "**Email Received From**: from_@email.com  \n"
        "**Email Received At**: 2025-04-16 10:10:10  \n"
        "**Email Subject**: <no subject> from from_@email.com  \n"
        "**Email Attachment Count**: 0  \n"
        "  \n"
        "Please consult the content section to view the email content."
    )

    # 1 file
    mocked_email.attachments = [pdf_file]
    report = list(converter.to_stix_objects(entity=mocked_email))[0]
    assert report.x_opencti_files == [
        {
            "name": "test.pdf",
            "mime_type": "application/pdf",
            "data": base64.b64encode(b"%PDF-1.4\nTest PDF Content"),
            "object_marking_refs": [converter.tlp_marking.id],
        }
    ]
    assert report.description == (
        "**Email Received From**: from_@email.com  \n"
        "**Email Received At**: 2025-04-16 10:10:10  \n"
        "**Email Subject**: <no subject> from from_@email.com  \n"
        "**Email Attachment Count**: 1  \n"
        "  \n"
        "Please consult the content section to view the email content."
    )

    # 2 files
    mocked_email.attachments = [pdf_file, csv_file]
    report = list(converter.to_stix_objects(entity=mocked_email))[0]
    assert report.x_opencti_files == [
        {
            "name": "test.pdf",
            "mime_type": "application/pdf",
            "data": base64.b64encode(b"%PDF-1.4\nTest PDF Content"),
            "object_marking_refs": [converter.tlp_marking.id],
        },
        {
            "name": "test.csv",
            "mime_type": "text/csv",
            "data": base64.b64encode(b"Test CSV Content"),
            "object_marking_refs": [converter.tlp_marking.id],
        },
    ]
    assert report.description == (
        "**Email Received From**: from_@email.com  \n"
        "**Email Received At**: 2025-04-16 10:10:10  \n"
        "**Email Subject**: <no subject> from from_@email.com  \n"
        "**Email Attachment Count**: 2  \n"
        "  \n"
        "Please consult the content section to view the email content."
    )

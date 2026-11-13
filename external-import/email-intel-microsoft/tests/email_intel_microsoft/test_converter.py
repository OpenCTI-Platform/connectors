import base64
import datetime
from unittest.mock import Mock

import pycti
import pytest
from email_intel_microsoft.converter import ConnectorConverter
from kiota_serialization_json.json_parse_node import JsonParseNode
from msgraph.generated.models.message import Message
from stix2 import TLPMarking
from stix2.utils import STIXdatetime

# Minimal but valid one-page PDF: raw bytes, as a mailbox attachment really is.
PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj\n"
    b"<< /Type /Catalog /Pages 2 0 R >>\n"
    b"endobj\n"
    b"2 0 obj\n"
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
    b"endobj\n"
    b"3 0 obj\n"
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\n"
    b"endobj\n"
    b"4 0 obj\n"
    b"<< /Length 68 >>\n"
    b"stream\n"
    b"BT /F1 12 Tf 50 780 Td (Email Intel Microsoft test attachment) Tj ET\n"
    b"endstream\n"
    b"endobj\n"
    b"5 0 obj\n"
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
    b"endobj\n"
    b"xref\n"
    b"0 6\n"
    b"0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000058 00000 n \n"
    b"0000000115 00000 n \n"
    b"0000000241 00000 n \n"
    b"0000000359 00000 n \n"
    b"trailer\n"
    b"<< /Size 6 /Root 1 0 R >>\n"
    b"startxref\n"
    b"429\n"
    b"%%EOF\n"
)


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


def test_converter_default_report_type(converter: ConnectorConverter) -> None:
    assert converter.report_type == "threat-report"


def test_converter_configurable_report_type(mocked_helper: Mock) -> None:
    converter = ConnectorConverter(
        helper=mocked_helper,
        author_name="Email Intel Microsoft",
        author_description="Email Intel Microsoft Connector",
        tlp_level="white",
        report_type="malware",
    )

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
    assert report[0].report_types == ["malware"]


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
    entity = Mock(
        subject="Test Report",
        received_date_time=datetime.datetime(2025, 4, 16),
        attachments=[],
    )
    entity._from = Mock(email_address=Mock())
    entity.from_.email_address.address = "Email address"
    converter._create_report = Mock(side_effect=ValueError("Test error"))

    report = list(converter.to_stix_objects(entity=entity))

    assert len(report) == 0
    converter.helper.connector_logger.warning.assert_called_once_with(
        "An error occurred while creating the Report, skipping...",
        meta={
            "email": {
                "subject": "Test Report",
                "received_date_time": datetime.datetime(2025, 4, 16),
                "from": "Email address",
            },
            "error": "Test error",
        },
    )


@pytest.mark.usefixtures("mock_email_intel_microsoft_config")
def test_converter_to_stix_with_attachment(converter: ConnectorConverter) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)
    pdf_file = Mock()
    pdf_file.name = "test.pdf"
    pdf_file.content_type = "application/pdf"
    pdf_file.content_bytes = b"%PDF-1.4\nTest PDF Content"

    csv_file = Mock()
    csv_file.name = "test.csv"
    csv_file.content_type = "text/csv"
    csv_file.content_bytes = b"Test CSV Content"

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


def test_converter_should_keep_pdf_attachment_when_kiota_decodes_content_bytes(
    converter: ConnectorConverter,
) -> None:
    """
    Graph sends `contentBytes` base64-encoded, and microsoft-kiota-serialization-json
    >= 1.12 decodes it, so `FileAttachment.content_bytes` holds the raw file bytes.
    """
    graph_message = {
        "id": "message-id",
        "subject": "Report with PDF",
        "receivedDateTime": "2025-04-16T10:10:10Z",
        "body": {"contentType": "html", "content": "<p>See attached</p>"},
        "from": {"emailAddress": {"address": "sender@example.com"}},
        "attachments": [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "id": "attachment-id",
                "name": "report.pdf",
                "contentType": "application/pdf",
                "contentBytes": base64.b64encode(PDF_BYTES).decode(),
            }
        ],
    }
    message = JsonParseNode(graph_message).get_object_value(Message)

    reports = list(converter.to_stix_objects(entity=message))

    assert len(reports) == 1
    assert len(reports[0].x_opencti_files) == 1
    assert reports[0].x_opencti_files[0]["name"] == "report.pdf"
    assert base64.b64decode(reports[0].x_opencti_files[0]["data"]) == PDF_BYTES

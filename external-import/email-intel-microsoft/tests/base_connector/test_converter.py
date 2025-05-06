import base64
import datetime
from typing import Any
from unittest.mock import Mock

import pycti
from base_connector.converter import BaseConverter
from base_connector.models import OpenCTIFile
from stix2 import TLPMarking
from stix2.utils import STIXdatetime


class Converter(BaseConverter):
    def to_stix_objects(self, _entity: Any) -> list[Any]:
        return []


def test_converter_author() -> None:
    converter = Converter(
        helper=Mock(),
        author_name="Author name",
        author_description="Author description",
        tlp_level="white",
    )

    assert converter.author.name == "Author name"
    assert converter.author.description == "Author description"
    assert converter.author.identity_class == "organization"
    assert converter.author.type == "identity"


def test_converter_tlp_marking() -> None:
    converter = Converter(
        helper=Mock(),
        author_name="Author name",
        author_description="Author description",
        tlp_level="white",
    )

    assert converter.tlp_marking.definition == TLPMarking(tlp="white")
    assert converter.tlp_marking.definition_type == "tlp"
    assert converter.tlp_marking.name == "TLP:WHITE"
    assert converter.tlp_marking.type == "marking-definition"


def test_converter_create_report() -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)

    converter = Converter(
        helper=Mock(),
        author_name="Author name",
        author_description="Author description",
        tlp_level="white",
    )

    report = converter._create_report(
        name="Test Report",
        published=published,
        report_types=["threat-report"],
        x_opencti_content="Test content",
        x_opencti_files=[
            OpenCTIFile(name="name", mime_type="text/plain", data=b"text")
        ],
    )

    assert report.id == pycti.Report.generate_id(
        name="Test Report", published=published
    )
    assert report.name == "Test Report"
    assert report.report_types == ["threat-report"]
    assert report.published == STIXdatetime(2025, 4, 16, 10, 10, 10)
    assert report.created_by_ref == converter.author.id
    assert report.object_refs == [converter.author.id]
    assert report.object_marking_refs == [converter.tlp_marking.id]
    assert report.x_opencti_content == "Test content"
    assert report.x_opencti_files == [
        {"name": "name", "mime_type": "text/plain", "data": base64.b64encode(b"text")}
    ]

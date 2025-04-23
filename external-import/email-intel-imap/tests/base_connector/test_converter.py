import datetime
from typing import Any
from unittest.mock import Mock

import pycti
import pytest
from base_connector.converter import BaseConverter
from stix2 import TLPMarking
from stix2.utils import STIXdatetime


class Converter(BaseConverter):
    author_name = "test name"
    author_description = "test description"

    def to_stix(self, _entity: Any) -> list[Any]:
        return []


def test_converter(mocked_config: Mock) -> None:
    converter = Converter(config=mocked_config, helper=Mock())

    assert converter.author_name
    assert converter.author_description


@pytest.mark.usefixtures("mocked_environ")
def test_converter_author(mocked_config: Mock) -> None:
    converter = Converter(config=mocked_config, helper=Mock())

    assert converter.author.name == converter.author_name
    assert converter.author.description == converter.author_description
    assert converter.author.identity_class == "organization"
    assert converter.author.type == "identity"


@pytest.mark.usefixtures("mocked_environ")
def test_converter_tlp_marking(mocked_config: Mock) -> None:
    converter = Converter(config=mocked_config, helper=Mock())

    assert converter.tlp_marking.definition == TLPMarking(tlp="white")
    assert converter.tlp_marking.definition_type == "tlp"
    assert converter.tlp_marking.name == "TLP:WHITE"
    assert converter.tlp_marking.type == "marking-definition"


@pytest.mark.usefixtures("mocked_environ")
def test_converter_create_report(mocked_config: Mock) -> None:
    published = datetime.datetime(2025, 4, 16, 10, 10, 10)

    converter = Converter(config=mocked_config, helper=Mock())

    report = converter._create_report(
        name="Test Report",
        published=published,
        report_types=["threat-report"],
        x_opencti_content="Test content",
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

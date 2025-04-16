import datetime
from unittest.mock import Mock

import pytest
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.connector import Connector
from email_intel_imap.converter import ConnectorConverter
from stix2.v21.vocab import REPORT_TYPE_THREAT_REPORT


@pytest.fixture(name="connector")
def fixture_connector(
    mocked_helper: Mock,
    mock_email_intel_imap_config: None,
) -> Connector:
    config = ConnectorConfig()
    return Connector(
        config=config,
        helper=mocked_helper,
        converter=ConnectorConverter(config=config, helper=mocked_helper),
        client=ConnectorClient(config=config, helper=mocked_helper),
    )


@pytest.mark.usefixtures("mocked_mail_box")
def test_connector_collect_intelligence_empty(connector: Connector) -> None:
    stix_objects = connector._collect_intelligence()
    assert stix_objects == []


def test_connector_collect_intelligence(
    connector: Connector, mocked_mail_box: Mock
) -> None:
    now = datetime.datetime.now()
    email1 = Mock(subject="email 1", date=now, text="email body 1")
    email2 = Mock(subject="email 2", date=now, text="email body 2")

    mocked_mail_box.fetch.return_value = [email1, email2]
    stix_objects = connector._collect_intelligence()

    assert len(stix_objects) == 2

    report = stix_objects[0]
    assert report.name == "email 1"
    assert str(report.published) == str(now)
    assert report.x_opencti_content == "email body 1"
    assert report.report_types == [REPORT_TYPE_THREAT_REPORT]
    assert report.created_by_ref == connector.converter.author.id
    assert report.object_refs == [connector.converter.author.id]
    assert report.object_marking_refs == [connector.converter.tlp_marking.id]

    report = stix_objects[1]
    assert report.name == "email 2"
    assert str(report.published) == str(now)
    assert report.x_opencti_content == "email body 2"
    assert report.report_types == [REPORT_TYPE_THREAT_REPORT]
    assert report.created_by_ref == connector.converter.author.id
    assert report.object_refs == [connector.converter.author.id]
    assert report.object_marking_refs == [connector.converter.tlp_marking.id]

import datetime
from unittest.mock import Mock

import pytest
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.connector import Connector
from email_intel_imap.converter import ConnectorConverter
from stix2.v21.vocab import REPORT_TYPE_THREAT_REPORT


@pytest.fixture(name="connector")
def fixture_connector(mocked_helper: Mock) -> Connector:
    config = ConnectorConfig()
    return Connector(
        config=config,
        helper=mocked_helper,
        converter=ConnectorConverter(
            helper=mocked_helper,
            author_name="Email Intel IMAP",
            author_description="Email Intel IMAP Connector",
            tlp_level=config.email_intel_imap.tlp_level,
        ),
        client=ConnectorClient(
            host=config.email_intel_imap.host,
            port=config.email_intel_imap.port,
            username=config.email_intel_imap.username,
            password=config.email_intel_imap.password,
            mailbox=config.email_intel_imap.mailbox,
        ),
    )


@pytest.mark.usefixtures("mock_email_intel_imap_config", "mocked_mail_box")
def test_connector_collect_intelligence_empty(connector: Connector) -> None:
    stix_objects = connector.collect_intelligence(None)
    assert stix_objects == []


@pytest.mark.usefixtures("mock_email_intel_imap_config")
def test_connector_collect_intelligence(
    connector: Connector, mocked_mail_box: Mock
) -> None:
    now = datetime.datetime.now()
    email1 = Mock(subject="email 1", date=now, text="email body 1")
    email2 = Mock(subject="email 2", date=now, text="email body 2")

    mocked_mail_box.fetch.return_value = [email1, email2]
    stix_objects = connector.collect_intelligence(None)

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

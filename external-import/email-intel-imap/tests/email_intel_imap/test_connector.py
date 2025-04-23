import datetime
from unittest.mock import Mock

import freezegun
import pytest
from base_connector import ConnectorError
from email_intel_imap.client import ConnectorClient
from email_intel_imap.config import ConnectorConfig
from email_intel_imap.connector import Connector
from email_intel_imap.converter import ConnectorConverter
from stix2.v21.vocab import REPORT_TYPE_THREAT_REPORT


@pytest.fixture(name="connector")
def fixture_connector(mocked_helper: Mock, test_config: ConnectorConfig) -> Connector:
    return Connector(
        config=test_config,
        helper=mocked_helper,
        converter=ConnectorConverter(
            helper=mocked_helper,
            author_name="Email Intel IMAP",
            author_description="Email Intel IMAP Connector",
            tlp_level=test_config.email_intel_imap.tlp_level,
        ),
        client=ConnectorClient(
            host=test_config.email_intel_imap.host,
            port=test_config.email_intel_imap.port,
            username=test_config.email_intel_imap.username,
            password=test_config.email_intel_imap.password,
            mailbox=test_config.email_intel_imap.mailbox,
        ),
    )


@pytest.mark.usefixtures("mocked_mail_box")
def test_connector_collect_intelligence_empty(connector: Connector) -> None:
    stix_objects = connector.collect_intelligence(None)
    assert stix_objects == []


def test_connector_collect_intelligence(
    connector: Connector, mocked_mail_box: Mock
) -> None:
    now = datetime.datetime.now(tz=datetime.UTC)
    email1 = Mock(subject="email 1", date=now, text="email body 1", attachments=[])
    email2 = Mock(subject="email 2", date=now, text="email body 2", attachments=[])

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


@freezegun.freeze_time("2025-04-22T14:00:00Z")
def test_connector_collect_intelligence_since_relative_from_date(
    connector: Connector, mocked_mail_box: Mock
) -> None:
    two_months_ago = datetime.datetime.fromisoformat("2025-02-22T12:00:00Z")
    today = datetime.datetime.fromisoformat("2025-04-22T12:00:00Z")

    email1 = Mock(subject="1", text="body 1", attachments=[], date=two_months_ago)
    email2 = Mock(subject="2", text="body 2", attachments=[], date=today)

    assert (
        connector.config.email_intel_imap.relative_import_start_date
        == datetime.timedelta(days=30)
    )

    mocked_mail_box.fetch.return_value = [email1, email2]
    stix_objects = connector.collect_intelligence(None)
    assert len(stix_objects) == 1
    assert stix_objects[0].name == "2"


@freezegun.freeze_time("2025-04-22T14:00:00Z")
def test_connector_collect_intelligence_since_last_run(
    connector: Connector, mocked_mail_box: Mock
) -> None:
    two_months_ago = datetime.datetime.fromisoformat("2025-02-22T12:00:00Z")
    two_days_ago = datetime.datetime.fromisoformat("2025-04-20T12:00:00Z")
    today = datetime.datetime.fromisoformat("2025-04-22T12:00:00Z")

    email1 = Mock(subject="1", text="body 1", attachments=[], date=two_months_ago)
    email2 = Mock(subject="2", text="body 2", attachments=[], date=two_days_ago)
    email3 = Mock(subject="3", text="body 3", attachments=[], date=today)

    assert (
        connector.config.email_intel_imap.relative_import_start_date
        == datetime.timedelta(days=30)
    )
    last_run = two_days_ago
    mocked_mail_box.fetch.return_value = [email1, email2, email3]
    stix_objects = connector.collect_intelligence(last_run)

    assert len(stix_objects) == 1

    report = stix_objects[0]
    assert report.name == "3"


def test_connector_known_warning(connector: Connector, mocked_mail_box: Mock) -> None:
    today = datetime.datetime.now(tz=datetime.UTC)
    connector.helper.get_state.return_value = {"last_run": "1970-01-01T00:00:00Z"}
    mocked_mail_box.fetch.return_value = [Mock(date=today)]

    assert (
        connector.process()
        == "An error occurred while creating the Report, skipping..."
    )


def test_connector_known_error(connector: Connector, mocked_mail_box: Mock) -> None:
    connector.helper.get_state.return_value = {"last_run": "1970-01-01T00:00:00Z"}
    mocked_mail_box.fetch.side_effect = ConnectorError("Known error")

    assert connector.process() == "Known error"


def test_connector_unknown_error(connector: Connector) -> None:
    assert connector.process() == "Unexpected error. See connector logs for details."

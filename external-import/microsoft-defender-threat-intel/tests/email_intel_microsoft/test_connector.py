import datetime
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import MagicMock, Mock

import freezegun
import pytest
from email_intel_microsoft.client import ConnectorClient
from email_intel_microsoft.config import ConnectorSettings
from email_intel_microsoft.connector import Connector
from email_intel_microsoft.converter import ConnectorConverter
from stix2.v21.vocab import REPORT_TYPE_THREAT_REPORT


@pytest.fixture(name="connector")
def fixture_connector(mocked_helper: Mock, test_config: ConnectorSettings) -> Connector:
    return Connector(
        config=test_config,
        helper=mocked_helper,
        converter=ConnectorConverter(
            helper=mocked_helper,
            author_name="Email Intel Microsoft",
            author_description="Email Intel Microsoft Connector",
            tlp_level=test_config.email_intel_microsoft.tlp_level,
        ),
        client=ConnectorClient(
            tenant_id=test_config.email_intel_microsoft.tenant_id,
            client_id=test_config.email_intel_microsoft.client_id,
            client_secret=test_config.email_intel_microsoft.client_secret,
            email=test_config.email_intel_microsoft.email,
            mailbox=test_config.email_intel_microsoft.mailbox,
            attachments_mime_types=test_config.email_intel_microsoft.attachments_mime_types,
        ),
    )


@pytest.mark.asyncio
def test_connector_process_data(
    connector: Connector,
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
    message: Callable[..., Any],
) -> None:
    email1 = message("message1", [])
    email2 = message("message2", [])

    connector.client._messages = messages_builder(
        [SimpleNamespace(value=[email1, email2], odata_next_link=None)]
    )

    stix_objects = connector.process_data()

    assert len(stix_objects) == 2

    report = stix_objects[0]
    assert report.name == "subject message1"
    assert str(report.published) == "2025-05-09 00:00:00+00:00"
    assert report.x_opencti_content == "body message1"
    assert report.report_types == [REPORT_TYPE_THREAT_REPORT]
    assert report.object_marking_refs == [connector.converter.tlp_marking.id]
    assert report.description == (
        "**Email Received From**: email@test.com  \n"
        "**Email Received At**: 2025-05-09 00:00:00+00:00  \n"
        "**Email Subject**: subject message1  \n"
        "**Email Attachment Count**: 0  \n"
        "  \n"
        "Please consult the content section to view the email content."
    )

    report = stix_objects[1]
    assert report.name == "subject message2"
    assert str(report.published) == "2025-05-09 00:00:00+00:00"
    assert report.x_opencti_content == "body message2"
    assert report.report_types == [REPORT_TYPE_THREAT_REPORT]
    assert report.object_marking_refs == [connector.converter.tlp_marking.id]
    assert report.description == (
        "**Email Received From**: email@test.com  \n"
        "**Email Received At**: 2025-05-09 00:00:00+00:00  \n"
        "**Email Subject**: subject message2  \n"
        "**Email Attachment Count**: 0  \n"
        "  \n"
        "Please consult the content section to view the email content."
    )


@freezegun.freeze_time("2025-04-22T14:00:00Z")
def test_connector_process_data_since_last_email_ingestion(
    connector: Connector,
) -> None:
    connector.client = MagicMock()

    connector.process_data()
    connector.client.fetch_from_relative_import_start_date.assert_called_once_with(
        datetime.datetime.fromisoformat("2025-03-23T14:00:00+00:00")
    )

    connector.helper.get_state.return_value = {
        "last_email_ingestion": "2025-04-22T14:00:00Z"
    }
    connector.process_data()
    connector.client.fetch_from_relative_import_start_date.assert_called_with(
        datetime.datetime.fromisoformat("2025-04-22T14:00:00+00:00")
    )

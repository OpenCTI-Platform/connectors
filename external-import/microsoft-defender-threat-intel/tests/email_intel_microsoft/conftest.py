import datetime
import os
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from email_intel_microsoft.config import ConnectorSettings
from msgraph.generated.models.file_attachment import FileAttachment
from pytest_mock import MockerFixture


@pytest.fixture(name="email_intel_config_dict")
def fixture_email_intel_config_dict() -> dict[str, dict[str, Any]]:
    return {
        "opencti": {
            "url": "http://test-opencti-url/",
            "token": "test-opencti-token",
        },
        "connector": {
            "id": "test-connector-id",
            "name": "External Import Connector Template",
            "type": "EXTERNAL_IMPORT",
            "scope": "ChangeMe",
            "duration_period": "P1D",
        },
        "email_intel_microsoft": {
            "tlp_level": "white",
            "relative_import_start_date": "P30D",
            "tenant_id": "tenant-id",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "email": "foo@bar.com",
            "mailbox": "INBOX",
            "attachments_mime_types": "application/pdf,text/csv,text/plain",
        },
    }


@pytest.fixture(name="mock_email_intel_microsoft_config")
def fixture_mock_email_intel_microsoft_config(
    mocker: MockerFixture, email_intel_config_dict: dict[str, dict[str, Any]]
) -> None:
    # Make sure the local config is not loaded in the tests
    ConnectorSettings.model_config["yaml_file"] = ""
    ConnectorSettings.model_config["env_file"] = ""

    environ = deepcopy(os.environ)
    for key, value in email_intel_config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


@pytest.fixture(name="messages_builder")
def fixture_messages_builder(
    attachment: Callable[..., FileAttachment],
) -> Callable[[list[SimpleNamespace]], MagicMock]:
    """
    Factory fixture to create a fake `.messages` request builder.
    Pages and downloads attachments in parallel.
    """

    def _factory(pages: list[SimpleNamespace]) -> MagicMock:
        builder: MagicMock = MagicMock()
        builder.get = AsyncMock(return_value=pages[0])
        if len(pages) > 1:
            remaining = pages[1:]

            async def _next() -> SimpleNamespace:
                return remaining.pop(0)

            builder.with_url.return_value.get = AsyncMock(side_effect=_next)

        attachment_builder: MagicMock = MagicMock()
        attachment_builder.get = AsyncMock(
            side_effect=lambda: attachment(with_bytes=True)
        )
        builder.by_message_id.return_value.attachments.by_attachment_id.return_value = (
            attachment_builder
        )
        return builder

    return _factory


@pytest.fixture(name="patch_graph_and_identity")
def fixture_patch_graph_and_identity(
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> tuple[MagicMock, MagicMock]:
    """Fixture to patch GraphServiceClient and ClientSecretCredential"""
    with patch("email_intel_microsoft.client.GraphServiceClient") as graph_mock, patch(
        "email_intel_microsoft.client.ClientSecretCredential"
    ) as cred_cls:
        cred_mock: MagicMock = MagicMock()
        cred_mock.close = AsyncMock()
        cred_cls.return_value = cred_mock
        yield graph_mock, cred_mock


@pytest.fixture(name="attachment")
def fixture_attachment() -> Callable[..., FileAttachment]:
    """Factory fixture to create a FileAttachment-spec mock."""

    def _factory(
        att_id: str = "att-1", mime: str = "image/png", *, with_bytes: bool = False
    ) -> FileAttachment:
        att: FileAttachment = MagicMock(spec=FileAttachment)
        att.id = att_id
        att.name = f"att f{att_id}"
        att.content_type = mime
        att.content_bytes = b"PRE" if with_bytes else None
        return att

    return _factory


@pytest.fixture(name="message")
def fixture_message(attachment: Callable[..., FileAttachment]) -> Callable[..., Any]:
    """Factory fixture to create a Message-like mock with attachments."""

    def _factory(
        msg_id: str = "msg-1",
        attachments: list[Any] | None = None,
        received_date_time=datetime.datetime.fromisoformat("2025-05-09T00:00:00Z"),
    ) -> Any:
        msg: Any = MagicMock()
        msg.id = msg_id
        msg.subject = f"subject {msg_id}"
        msg.from_ = Mock(email_address=Mock(address="email@test.com"))
        msg.received_date_time = received_date_time
        msg.body = Mock(content=f"body {msg_id}")
        msg.attachments = attachments if attachments is not None else [attachment()]
        return msg

    return _factory


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> Mock:
    helper = mocker.patch("pycti.OpenCTIConnectorHelper", MagicMock())
    helper.connect_id = "test-connector-id"
    helper.connect_name = "Test Connector"
    helper.api.work.initiate_work.return_value = "work-id"
    helper.get_state.return_value = {}
    helper.stix2_create_bundle.return_value = "bundle"
    return helper


@pytest.fixture(name="test_config")
def fixture_test_config(
    mock_email_intel_microsoft_config: None,
) -> ConnectorSettings:
    return ConnectorSettings()

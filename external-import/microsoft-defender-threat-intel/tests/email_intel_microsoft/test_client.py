import datetime
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import MagicMock

import pytest
from email_intel_microsoft.client import ConnectorClient
from msgraph.generated.models.file_attachment import (
    FileAttachment,
)


def test_sync_fetch_two_messages_mixed_attachments(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    message: Callable[..., Any],
    attachment: Callable[..., FileAttachment],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> None:
    """Two messages: one with a file attachment, one without."""
    graph_mock, _ = patch_graph_and_identity
    page = SimpleNamespace(
        value=[
            message("msg-with", [attachment("a1")]),
            message("msg-without", []),
        ],
        odata_next_link=None,
    )
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = messages_builder(
        [page]
    )
    client = ConnectorClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        email="user@test",
        mailbox="INBOX",
        attachments_mime_types=["image/png"],
    )
    results = client.fetch_from_relative_import_start_date(
        datetime.datetime.now(tz=datetime.UTC)
    )
    assert [m.id for m in results] == ["msg-with", "msg-without"]
    message = results[0]
    assert message.id == "msg-with"
    assert message.subject == "subject msg-with"
    assert message.body.content == "body msg-with"
    assert message.attachments[0].id == "a1"
    assert message.attachments[0].content_type == "image/png"
    assert message.attachments[0].content_bytes == b"PRE"

    message = results[1]
    assert message.id == "msg-without"
    assert message.subject == "subject msg-without"
    assert message.body.content == "body msg-without"
    assert message.attachments == []


def test_sync_fetch_two_attachments_single_message(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    message: Callable[..., Any],
    attachment: Callable[..., FileAttachment],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> None:
    """Single message with two file attachments."""
    graph_mock, _ = patch_graph_and_identity
    msg = message("two-files", [attachment("a1"), attachment("a2")])
    page = SimpleNamespace(value=[msg], odata_next_link=None)
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = messages_builder(
        [page]
    )
    client = ConnectorClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        email="user@test",
        mailbox="INBOX",
        attachments_mime_types=["image/png"],
    )
    [result_msg] = client.fetch_from_relative_import_start_date(
        datetime.datetime.now(tz=datetime.UTC)
    )
    assert result_msg.id == "two-files"
    assert result_msg.subject == "subject two-files"
    assert result_msg.body.content == "body two-files"
    assert len(result_msg.attachments) == 2
    assert result_msg.attachments[0].id == "a1"
    assert result_msg.attachments[0].content_type == "image/png"
    assert result_msg.attachments[0].content_bytes == b"PRE"
    assert result_msg.attachments[1].id == "a2"
    assert result_msg.attachments[1].content_type == "image/png"
    assert result_msg.attachments[1].content_bytes == b"PRE"


@pytest.mark.asyncio
async def test_async_fetch_pagination(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    message: Callable[..., Any],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> None:
    """Async fetch should page through multiple results."""
    graph_mock, _ = patch_graph_and_identity
    pages = [
        SimpleNamespace(value=[message("p1")], odata_next_link="next"),
        SimpleNamespace(value=[message("p2")], odata_next_link=None),
    ]
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = messages_builder(
        pages
    )
    client = ConnectorClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        email="user@test",
        mailbox="INBOX",
        attachments_mime_types=["image/png"],
    )
    async with client:
        results = await client._fetch_from_relative_import_start_date(
            datetime.datetime.now(tz=datetime.UTC)
        )
    assert [m.id for m in results] == ["p1", "p2"]


def test_sync_wrapper_awaits_close(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> None:
    """Sync wrapper must await credential.close()."""
    graph_mock, cred_mock = patch_graph_and_identity
    empty = SimpleNamespace(value=[], odata_next_link=None)
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = messages_builder(
        [empty]
    )
    client = ConnectorClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        email="user@test",
        mailbox="INBOX",
        attachments_mime_types=["image/png"],
    )
    client.fetch_from_relative_import_start_date(datetime.datetime.now(tz=datetime.UTC))
    cred_mock.close.assert_awaited_once()


def test_mime_type_filter(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    message: Callable[..., Any],
    attachment: Callable[..., FileAttachment],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> None:
    """Only allow downloading attachments with permitted MIME types."""
    graph_mock, _ = patch_graph_and_identity
    allowed = attachment("ok", "image/png")
    blocked = attachment("block", "application/pdf")
    page = SimpleNamespace(
        value=[message("msg", [allowed, blocked])], odata_next_link=None
    )
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = messages_builder(
        [page]
    )
    client = ConnectorClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        email="user@test",
        mailbox="INBOX",
        attachments_mime_types=["image/png"],
    )
    [result_msg] = client.fetch_from_relative_import_start_date(
        datetime.datetime.now(tz=datetime.UTC)
    )
    assert result_msg.attachments[0].content_bytes == b"PRE"
    assert result_msg.attachments[1].content_bytes is None

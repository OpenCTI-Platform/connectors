import asyncio
import base64
import datetime
import logging
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from email_intel_microsoft.client import (
    MAX_CONCURRENT_ATTACHMENT_DOWNLOADS,
    ConnectorClient,
)
from kiota_serialization_json.json_parse_node import JsonParseNode
from msgraph.generated.models.file_attachment import (
    FileAttachment,
)
from msgraph.generated.models.message_collection_response import (
    MessageCollectionResponse,
)
from msgraph.generated.models.o_data_errors.main_error import MainError
from msgraph.generated.models.o_data_errors.o_data_error import ODataError


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


def test_attachment_downloads_should_never_exceed_mailbox_concurrency_limit(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    message: Callable[..., Any],
    attachment: Callable[..., FileAttachment],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> None:
    """Graph throttles (429 MailboxConcurrency) beyond 4 concurrent requests per mailbox."""
    graph_mock, _ = patch_graph_and_identity
    attachments = [attachment(f"a{i}") for i in range(10)]
    page = SimpleNamespace(value=[message("msg", attachments)], odata_next_link=None)
    messages = messages_builder([page])
    in_flight = 0
    max_in_flight = 0

    def _tracked_builder(att_id: str) -> MagicMock:
        async def _tracked_get() -> FileAttachment:
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0)  # yield so that every started download overlaps
            in_flight -= 1
            return attachment(att_id, with_bytes=True)

        return MagicMock(get=AsyncMock(side_effect=_tracked_get))

    messages.by_message_id.return_value.attachments.by_attachment_id.side_effect = (
        _tracked_builder
    )
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = (
        messages
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

    assert max_in_flight == MAX_CONCURRENT_ATTACHMENT_DOWNLOADS == 4
    assert [a.content_bytes for a in result_msg.attachments] == [b"PRE"] * 10


def test_attachment_should_be_skipped_when_its_download_fails_permanently(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    message: Callable[..., Any],
    attachment: Callable[..., FileAttachment],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An attachment gone from the mailbox (404) must not abort the whole run."""
    graph_mock, _ = patch_graph_and_identity
    page = SimpleNamespace(
        value=[message("msg", [attachment("ok"), attachment("gone")])],
        odata_next_link=None,
    )
    messages = messages_builder([page])
    not_found = ODataError(
        error=MainError(
            code="ErrorItemNotFound",
            message="The specified object was not found in the store.",
        ),
        response_status_code=404,
    )
    builders = {
        "ok": MagicMock(get=AsyncMock(return_value=attachment(with_bytes=True))),
        "gone": MagicMock(get=AsyncMock(side_effect=not_found)),
    }
    messages.by_message_id.return_value.attachments.by_attachment_id.side_effect = (
        builders.get
    )
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = (
        messages
    )
    client = ConnectorClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        email="user@test",
        mailbox="INBOX",
        attachments_mime_types=["image/png"],
    )

    with caplog.at_level(logging.WARNING, logger="email_intel_microsoft.client"):
        [result_msg] = client.fetch_from_relative_import_start_date(
            datetime.datetime.now(tz=datetime.UTC)
        )

    assert result_msg.id == "msg"
    assert result_msg.attachments[0].content_bytes == b"PRE"
    assert result_msg.attachments[1].content_bytes is None
    assert "ErrorItemNotFound" in caplog.text
    assert "att fgone" in caplog.text


def test_transient_attachment_download_error_should_propagate(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    message: Callable[..., Any],
    attachment: Callable[..., FileAttachment],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> None:
    """
    A throttled download (429 once the Graph client retries are exhausted) must fail
    the run, so the state is not advanced and the next run retries the email.
    """
    graph_mock, _ = patch_graph_and_identity
    page = SimpleNamespace(
        value=[message("msg", [attachment("ok"), attachment("throttled")])],
        odata_next_link=None,
    )
    messages = messages_builder([page])
    throttled = ODataError(
        error=MainError(
            code="ApplicationThrottled",
            message="Application is over its MailboxConcurrency limit.",
        ),
        response_status_code=429,
    )
    builders = {
        "ok": MagicMock(get=AsyncMock(return_value=attachment(with_bytes=True))),
        "throttled": MagicMock(get=AsyncMock(side_effect=throttled)),
    }
    messages.by_message_id.return_value.attachments.by_attachment_id.side_effect = (
        builders.get
    )
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = (
        messages
    )
    client = ConnectorClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        email="user@test",
        mailbox="INBOX",
        attachments_mime_types=["image/png"],
    )

    with pytest.raises(ODataError) as exc_info:
        client.fetch_from_relative_import_start_date(
            datetime.datetime.now(tz=datetime.UTC)
        )

    assert exc_info.value.response_status_code == 429


def _graph_file_attachment(att_id: str, content: bytes | None = None) -> dict[str, Any]:
    payload = {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "id": att_id,
        "name": f"{att_id}.txt",
        "contentType": "text/plain",
    }
    if content is not None:
        payload["contentBytes"] = base64.b64encode(content).decode()
    return payload


def test_attachment_download_should_not_reenter_the_message_backing_store(
    patch_graph_and_identity: tuple[MagicMock, MagicMock],
    messages_builder: Callable[[list[SimpleNamespace]], MagicMock],
) -> None:
    """
    Regression for microsoftgraph/msgraph-sdk-python#954. The listed attachments are
    tracked by the message's kiota backing store: mutating one re-enters the
    message's set(), which spins the CPU with microsoft-kiota-abstractions 1.12.x.
    Loading the content must leave the message's backing store untouched.
    """
    graph_mock, _ = patch_graph_and_identity
    page = JsonParseNode(
        {
            "value": [
                {
                    "id": "msg-1",
                    "subject": "Report",
                    "attachments": [
                        _graph_file_attachment("a1"),
                        _graph_file_attachment("a2"),
                    ],
                }
            ]
        }
    ).get_object_value(MessageCollectionResponse)
    downloads = {
        "a1": JsonParseNode(_graph_file_attachment("a1", b"one")).get_object_value(
            FileAttachment
        ),
        "a2": JsonParseNode(_graph_file_attachment("a2", b"two")).get_object_value(
            FileAttachment
        ),
    }
    messages = messages_builder([page])
    messages.by_message_id.return_value.attachments.by_attachment_id.side_effect = (
        lambda att_id: MagicMock(get=AsyncMock(return_value=downloads[att_id]))
    )
    graph_mock.return_value.users.by_user_id.return_value.mail_folders.by_mail_folder_id.return_value.messages = (
        messages
    )
    message_store = page.value[0].backing_store
    message_store_set_keys: list[str] = []
    original_set = message_store.set

    def _spy_set(key: str, value: Any) -> None:
        message_store_set_keys.append(key)
        original_set(key, value)

    message_store.set = _spy_set  # type: ignore[method-assign]
    client = ConnectorClient(
        tenant_id="tenant-id",
        client_id="client-id",
        client_secret="client-secret",
        email="user@test",
        mailbox="INBOX",
        attachments_mime_types=["text/plain"],
    )

    [result_msg] = client.fetch_from_relative_import_start_date(
        datetime.datetime.now(tz=datetime.UTC)
    )

    assert message_store_set_keys == []
    assert [(a.id, a.content_bytes) for a in result_msg.attachments] == [
        ("a1", b"one"),
        ("a2", b"two"),
    ]

import datetime
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from email_intel_microsoft.client import ConnectorClient, _suspend_backed_model_lambdas
from kiota_abstractions.store.backed_model import BackedModel
from kiota_abstractions.store.in_memory_backing_store import InMemoryBackingStore
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


@dataclass
class _FakeBackedItem(BackedModel):
    """Minimal BackedModel used to reproduce the InMemoryBackingStore bug in isolation."""

    content_bytes: bytes | None = field(default=None)


def test_suspend_backed_model_lambdas_prevents_infinite_loop() -> None:
    """
    Reproduces the microsoft-kiota-abstractions InMemoryBackingStore infinite-loop bug
    (https://github.com/microsoftgraph/msgraph-sdk-python/issues/954) and verifies that
    `_suspend_backed_model_lambdas` prevents mutating an item inside a tracked collection
    from re-triggering the parent store's `set()`.
    """
    parent_store = InMemoryBackingStore()
    item = _FakeBackedItem(backing_store=InMemoryBackingStore())

    set_call_count = 0
    original_set = parent_store.set

    def _counting_set(key: str, value: Any) -> None:
        nonlocal set_call_count
        set_call_count += 1
        original_set(key, value)

    parent_store.set = _counting_set  # type: ignore[method-assign]

    # Simulate what InMemoryBackingStore.set() does when `message.attachments = [item]`:
    # it subscribes a lambda on the item's backing store that re-invokes the parent's set().
    item.backing_store.subscribe(
        lambda prop_key, old_val, new_val: parent_store.set("attachments", [item])
    )
    parent_store.set("attachments", [item])
    baseline_calls = set_call_count

    # Without the workaround, mutating `item.content_bytes` re-triggers the parent's
    # set() - this is the reported bug.
    item.content_bytes = b"data"
    assert set_call_count > baseline_calls

    # The workaround must prevent the parent's set() from being retriggered.
    set_call_count = 0
    with _suspend_backed_model_lambdas(item):
        item.content_bytes = b"more data"
    assert set_call_count == 0
    assert item.content_bytes == b"more data"

    # Subscriptions must be restored once the context manager exits.
    item.content_bytes = b"final"
    assert set_call_count > 0

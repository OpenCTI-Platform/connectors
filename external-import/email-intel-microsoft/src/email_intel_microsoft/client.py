import asyncio
import datetime
import logging
from contextlib import contextmanager
from typing import Any, Iterator

from azure.identity.aio import ClientSecretCredential
from base_connector import BaseClient
from base_connector.errors import ConnectorError
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph import GraphServiceClient
from msgraph.generated.models.attachment import (
    Attachment,
)
from msgraph.generated.models.file_attachment import (
    FileAttachment,
)
from msgraph.generated.models.message import (
    Message,
)
from msgraph.generated.models.message_collection_response import (
    MessageCollectionResponse,
)
from msgraph.generated.users.item.mail_folders.item.messages.messages_request_builder import (
    MessagesRequestBuilder,
)
from msgraph.generated.users.item.mail_folders.mail_folders_request_builder import (
    MailFoldersRequestBuilder,
)

logger = logging.getLogger(__name__)


@contextmanager
def _suspend_backed_model_lambdas(backed_item: Any) -> Iterator[None]:
    """
    Defensive workaround for a microsoft-kiota-abstractions InMemoryBackingStore
    infinite-loop bug (see https://github.com/microsoftgraph/msgraph-sdk-python/issues/954,
    open since 2024-11-16, no fixed release available at the time of writing).

    `InMemoryBackingStore.set()` subscribes a *new* lambda on every item of a list-typed
    property every time the property is set, with no guard against duplicate
    subscriptions. Each subscribed lambda re-invokes `set()` on the parent store, so
    mutating a single attribute on an item that lives inside an already-tracked
    collection (e.g. `file_attachment.content_bytes = ...` where `file_attachment` is
    part of `message.attachments`) re-triggers the parent's `set()`, which re-subscribes
    yet more lambdas onto every item -> unbounded CPU spin, and the connector getting
    stuck (last_run_datetime/next_run_datetime never updated, Work stuck in progress).

    We temporarily unsubscribe the (private/name-mangled) lambda subscriptions from the
    item's own backing store before mutating it, then restore them afterwards -
    mirroring the community workaround documented in msgraph-sdk-python#954, so dirty
    tracking keeps working normally for any code running after this block.

    NOTE: relies on the private attribute `_InMemoryBackingStore__subscriptions`
    (name-mangled), which is fragile across `microsoft-kiota-abstractions` versions.
    Remove this workaround once the upstream bug is fixed.
    """
    backing_store = getattr(backed_item, "backing_store", None)
    subscriptions = (
        getattr(backing_store, "_InMemoryBackingStore__subscriptions", None)
        if backing_store is not None
        else None
    )
    if not subscriptions:
        yield
        return

    suspended = [
        (subscription_id, callback)
        for subscription_id, callback in list(subscriptions.items())
        if getattr(callback, "__name__", None) == "<lambda>"
    ]
    for subscription_id, _ in suspended:
        backing_store.unsubscribe(subscription_id)
    try:
        yield
    finally:
        for subscription_id, callback in suspended:
            backing_store.subscribe(callback, subscription_id)


class ConnectorClient(BaseClient):
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        email: str,
        mailbox: str,
        attachments_mime_types: list[str],
    ) -> None:
        super().__init__()
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._email = email
        self._mailbox = mailbox
        self._attachments_mime_types = attachments_mime_types

        self._credentials: ClientSecretCredential | None = None
        self._client: GraphServiceClient | None = None
        self._folder_id: str | None = None

    async def __aenter__(self) -> "ConnectorClient":
        """Opens Azure credential with async context manager."""
        self._credentials = ClientSecretCredential(
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )
        self._client = GraphServiceClient(credentials=self._credentials)
        self._folder_id = await self.get_folder_id_by_name(self._mailbox)
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        """Closes the Graph client."""
        await self._credentials.close()

    async def get_folder_id_by_name(self, mailbox: str) -> str:
        """Retrieve the folder ID for a given mailbox name."""
        if mailbox == "INBOX":
            return "inbox"

        query_params = (
            MailFoldersRequestBuilder.MailFoldersRequestBuilderGetQueryParameters(
                filter=f"displayName eq '{mailbox}'"
            )
        )
        folders_response = await self._client.users.by_user_id(
            self._email
        ).mail_folders.get(
            request_configuration=RequestConfiguration(query_parameters=query_params)
        )
        for folder in folders_response.value:
            if folder.display_name == mailbox:
                return folder.id
        raise ConnectorError(f"Folder '{mailbox}' not found for user '{self._email}'.")

    async def _load_file_attachments(self, message: Message) -> None:
        """Download *FileAttachment* concurrently via `asyncio.gather`."""

        def _is_supported(content_type: str | None) -> bool:
            if content_type not in self._attachments_mime_types:
                logger.info(
                    "%s not in EMAIL_INTEL_ATTACHMENTS_MIME_TYPES%s, skipping...",
                    content_type,
                    self._attachments_mime_types,
                )
                return False
            return True

        if not message.attachments:
            return

        async def _download(file_attachment: FileAttachment) -> None:
            attachment: Attachment = await (
                self._client.users.by_user_id(self._email)
                .mail_folders.by_mail_folder_id(self._folder_id)
                .messages.by_message_id(message.id)
                .attachments.by_attachment_id(file_attachment.id)
                .get()
            )
            if isinstance(attachment, FileAttachment):
                with _suspend_backed_model_lambdas(file_attachment):
                    file_attachment.content_bytes = attachment.content_bytes or b""

        # * unpacks the generator so every coroutine becomes
        # a separate positional arg to asyncio.gather()
        await asyncio.gather(
            *(
                _download(attachment)
                for attachment in message.attachments
                if isinstance(attachment, FileAttachment)
                and _is_supported(attachment.content_type)
            )
        )

    async def _fetch_from_relative_import_start_date(
        self,
        since_datetime: datetime.datetime,
        page_size: int = 50,
    ) -> list[Message]:
        """
        Fetches messages received since a given datetime.

        Retrieves all messages from the inbox that were received after the specified datetime,
        handling pagination and loading file attachments for each message.
        """
        query_parameters = (
            MessagesRequestBuilder.MessagesRequestBuilderGetQueryParameters(
                select=[
                    "id",
                    "subject",
                    "body",
                    "receivedDateTime",
                    "from",
                    "attachments",
                ],
                filter=f"receivedDateTime ge {since_datetime.isoformat()}",
                orderby=["receivedDateTime desc"],
                expand=["attachments($select=id,name,contentType)"],
                top=page_size,
            )
        )

        page: MessageCollectionResponse = await (
            self._client.users.by_user_id(self._email)
            .mail_folders.by_mail_folder_id(self._folder_id)
            .messages.get(
                request_configuration=RequestConfiguration(
                    query_parameters=query_parameters
                )
            )
        )
        messages = []
        while page:
            for message in page.value or []:
                await self._load_file_attachments(message=message)
                messages.append(message)

            if not page.odata_next_link:
                break
            page = await (
                self._client.users.by_user_id(self._email)
                .mail_folders.by_mail_folder_id(self._folder_id)
                .messages.with_url(raw_url=page.odata_next_link)
                .get()
            )
        return messages

    def fetch_from_relative_import_start_date(
        self, since_datetime: datetime.datetime, page_size: int = 50
    ) -> list[Message]:
        """
        This method wraps an asynchronous call to the Microsoft Graph API to fetch messages
        from a user's mailbox starting from a specific datetime.

        Due to limitations in `asyncio.run()` when used in environments where an event loop
        may already be running (e.g., in web servers, background tasks, or notebooks),
        this implementation uses a safer event loop retrieval strategy. For more details, see:
        https://github.com/microsoftgraph/msgraph-sdk-python/issues/366
        """

        async def _run() -> list[Message]:
            async with self:  # Ensure the client is closed after use
                return await self._fetch_from_relative_import_start_date(
                    since_datetime, page_size=page_size
                )

        try:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(_run())
        except RuntimeError as e:
            if "There is no current event loop in thread" in str(e):
                return asyncio.run(_run())
            raise

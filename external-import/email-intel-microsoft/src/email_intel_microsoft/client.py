import asyncio
import datetime
import logging
from typing import Any

from azure.identity.aio import ClientSecretCredential
from base_connector import BaseClient
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

logger = logging.getLogger(__name__)


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
        self._email = email
        self._attachments_mime_types = attachments_mime_types

        # Azure credential (aio flavour → must be closed)
        self._credentials = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        # Root Graph client
        self._messages = (
            GraphServiceClient(credentials=self._credentials)
            .users.by_user_id(self._email)
            .mail_folders.by_mail_folder_id(mailbox)
            .messages
        )

    async def __aenter__(self) -> "ConnectorClient":
        """Opens Azure credential with async context manager."""
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        """Closes the underlying Azure credential when the ConnectorClient is used as an async context manager."""
        await self._credentials.close()

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
                self._messages.by_message_id(message.id)
                .attachments.by_attachment_id(file_attachment.id)
                .get()
            )
            if isinstance(attachment, FileAttachment):
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

        page: MessageCollectionResponse = await self._messages.get(
            request_configuration=RequestConfiguration(
                query_parameters=query_parameters
            )
        )
        messages = []
        while page:
            for message in page.value or []:
                await self._load_file_attachments(message=message)
                messages.append(message)

            if not page.odata_next_link:
                break
            page = await self._messages.with_url(raw_url=page.odata_next_link).get()
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

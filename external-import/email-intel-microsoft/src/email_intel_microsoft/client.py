import asyncio
import datetime
import logging
from typing import Any

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
from msgraph.generated.models.o_data_errors.o_data_error import ODataError
from msgraph.generated.users.item.mail_folders.item.messages.messages_request_builder import (
    MessagesRequestBuilder,
)
from msgraph.generated.users.item.mail_folders.mail_folders_request_builder import (
    MailFoldersRequestBuilder,
)

logger = logging.getLogger(__name__)

# Graph allows at most 4 concurrent requests per application and mailbox
# (MailboxConcurrency); beyond that it answers 429 ApplicationThrottled.
MAX_CONCURRENT_ATTACHMENT_DOWNLOADS = 4

# Transient Graph errors, the same codes the kiota RetryHandler retries.
TRANSIENT_STATUS_CODES = frozenset({429, 503, 504})


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
        """
        Download *FileAttachment* concurrently via `asyncio.gather`, at most
        MAX_CONCURRENT_ATTACHMENT_DOWNLOADS at a time.
        """

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

        attachments = message.attachments
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_ATTACHMENT_DOWNLOADS)

        async def _download(index: int, file_attachment: FileAttachment) -> None:
            async with semaphore:
                try:
                    attachment: Attachment = await (
                        self._client.users.by_user_id(self._email)
                        .mail_folders.by_mail_folder_id(self._folder_id)
                        .messages.by_message_id(message.id)
                        .attachments.by_attachment_id(file_attachment.id)
                        .get()
                    )
                except ODataError as e:
                    if e.response_status_code in TRANSIENT_STATUS_CODES:
                        # Retries exhausted on a transient error: fail the run so the
                        # state is not advanced and the next run retries this email.
                        raise
                    # Permanent error (e.g. 404, attachment deleted meanwhile): skip
                    # this attachment rather than failing every future run on it.
                    logger.warning(
                        "Could not download attachment %s of message %s, skipping it: %s",
                        file_attachment.name,
                        message.id,
                        e.error.code if e.error else e,
                    )
                    return
            if isinstance(attachment, FileAttachment):
                if attachment.content_bytes is None:
                    attachment.content_bytes = b""
                # Replace the listed attachment rather than setting content_bytes on it.
                # The listed one is tracked by the message's kiota backing store, and
                # mutating it re-enters the message's set(), which spins the CPU with
                # microsoft-kiota-abstractions 1.12.x (msgraph-sdk-python#954). Item
                # assignment on the list goes through no backing store.
                attachments[index] = attachment

        # * unpacks the generator so every coroutine becomes
        # a separate positional arg to asyncio.gather()
        results = await asyncio.gather(
            *(
                _download(index, attachment)
                for index, attachment in enumerate(attachments)
                if isinstance(attachment, FileAttachment)
                and _is_supported(attachment.content_type)
            ),
            # Let every download finish before re-raising, so no task is left
            # pending on the event loop that the next run reuses.
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                raise result

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
